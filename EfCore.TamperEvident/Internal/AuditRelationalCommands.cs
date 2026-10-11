using System.Collections.Concurrent;
using System.Data.Common;
using System.Globalization;
using System.Text;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// The commands on the hot path of every audited save, built once per model and reused.
    /// </summary>
    /// <remarks>
    /// They go through EF Core's own command pipeline (logging, diagnostics and command interceptors included), but the SQL
    /// and the parameter definitions are prepared once instead of on every call, the parameters use the exact column type
    /// mappings of the model, and the chain head is read without query compilation or materialization. The new entries and
    /// the advanced chain heads are written with a single command (one round trip). The prepared commands are templates:
    /// like EF Core's own query cache, every execution rents a command from the connection and fills it from the template,
    /// because a command instance must not be used by two contexts at the same time.
    /// </remarks>
    internal sealed class AuditRelationalCommands
    {
        private readonly IRelationalCommandBuilderFactory _factory;
        private readonly ISqlGenerationHelper _helper;
        private readonly AuditSqlCommands _sql;
        private readonly (RelationalTypeMapping Mapping, bool Nullable)[] _logParameters;
        private readonly (RelationalTypeMapping Mapping, bool Nullable)[] _headParameters;
        private readonly (RelationalTypeMapping Mapping, bool Nullable) _tableParameter;
        private readonly ConcurrentDictionary<(int Rows, int Heads), IRelationalCommandTemplate> _appendCommands = new();
        private readonly string[] _parameterNames;
        private readonly int _maxParameters;
        private IRelationalCommandTemplate? _lock;

        public AuditRelationalCommands(DbContext context, AuditSqlCommands sql, DatabaseProvider provider)
        {
            _factory = context.GetService<IRelationalCommandBuilderFactory>();
            _helper = context.GetService<ISqlGenerationHelper>();
            _sql = sql;

            var log = context.Model.FindEntityType(typeof(AuditLog))!;
            _logParameters = AuditSqlCommands.LogColumnNames.Select(name => Mapping(log, name)).ToArray();

            var chain = context.Model.FindEntityType(typeof(AuditChainState))!;
            _headParameters = new[]
            {
                nameof(AuditChainState.LastHash), nameof(AuditChainState.UnanchoredCount), nameof(AuditChainState.LastModified),
                nameof(AuditChainState.LastSequence), nameof(AuditChainState.KeyId), nameof(AuditChainState.Mac), nameof(AuditChainState.TableName)
            }.Select(name => Mapping(chain, name)).ToArray();
            _tableParameter = Mapping(chain, nameof(AuditChainState.TableName));

            // SQL Server accepts 2100 parameters per command; SQLite (as compiled by older systems) only 999.
            var maxParameters = provider switch
            {
                DatabaseProvider.SqlServer => 2000,
                DatabaseProvider.Sqlite => 990,
                _ => 4000
            };
            _maxParameters = maxParameters;
            MaxRowsPerCommand = Math.Min(200, (maxParameters - 4 * _headParameters.Length) / _logParameters.Length);

            _parameterNames = Enumerable.Range(0, maxParameters + 1).Select(i => "p" + i.ToString(CultureInfo.InvariantCulture)).ToArray();
        }

        /// <summary>How many entries one command appends at most.</summary>
        public int MaxRowsPerCommand { get; }

        #region Chain heads

        public async Task<AuditChainState?> SelectForUpdateAsync(DbContext context, string table, CancellationToken cancellationToken)
        {
            var (connection, command) = Rent(context, LockCommand());
            try
            {
                await using var reader = await command.ExecuteReaderAsync(
                    Parameters(context, connection, new Dictionary<string, object?> { ["p0"] = table }), cancellationToken).ConfigureAwait(false);
                return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? ReadHead(reader.DbDataReader) : null;
            }
            finally
            {
                connection.ReturnCommand(command);
            }
        }

        public AuditChainState? SelectForUpdate(DbContext context, string table)
        {
            var (connection, command) = Rent(context, LockCommand());
            try
            {
                using var reader = command.ExecuteReader(Parameters(context, connection, new Dictionary<string, object?> { ["p0"] = table }));
                return reader.Read() ? ReadHead(reader.DbDataReader) : null;
            }
            finally
            {
                connection.ReturnCommand(command);
            }
        }

        // Columns in the order of AuditSqlCommands.HeadColumns. The last modification time is not needed: it is overwritten.
        private static AuditChainState ReadHead(DbDataReader reader) => new()
        {
            TableName = reader.GetString(0),
            LastHash = reader.GetString(1),
            UnanchoredCount = Convert.ToInt32(reader.GetValue(2), CultureInfo.InvariantCulture),
            LastSequence = Convert.ToInt64(reader.GetValue(3), CultureInfo.InvariantCulture),
            KeyId = reader.IsDBNull(4) ? null : reader.GetString(4),
            Mac = reader.IsDBNull(5) ? null : reader.GetString(5)
        };

        private IRelationalCommandTemplate LockCommand() => _lock ??= Build(
            string.Format(CultureInfo.InvariantCulture, _sql.SelectHeadForUpdate, Placeholder(0)),
            new[] { _tableParameter });

        #endregion

        #region Appending entries

        public async Task AppendAsync(DbContext context, IReadOnlyList<AuditLog> logs, IReadOnlyList<AuditChainState> heads, CancellationToken cancellationToken)
        {
            for (var (row, head) = (0, 0); row < logs.Count || head < heads.Count;)
            {
                var (rows, headCount) = NextChunk(logs.Count - row, heads.Count - head);
                var (template, values) = Prepare(context, logs, row, rows, heads, head, headCount);
                var (connection, command) = Rent(context, template);
                try
                {
                    Check(await command.ExecuteNonQueryAsync(Parameters(context, connection, values), cancellationToken).ConfigureAwait(false),
                        rows, heads, head, headCount);
                }
                finally
                {
                    connection.ReturnCommand(command);
                }

                row += rows;
                head += headCount;
            }
        }

        public void Append(DbContext context, IReadOnlyList<AuditLog> logs, IReadOnlyList<AuditChainState> heads)
        {
            for (var (row, head) = (0, 0); row < logs.Count || head < heads.Count;)
            {
                var (rows, headCount) = NextChunk(logs.Count - row, heads.Count - head);
                var (template, values) = Prepare(context, logs, row, rows, heads, head, headCount);
                var (connection, command) = Rent(context, template);
                try
                {
                    Check(command.ExecuteNonQuery(Parameters(context, connection, values)), rows, heads, head, headCount);
                }
                finally
                {
                    connection.ReturnCommand(command);
                }

                row += rows;
                head += headCount;
            }
        }

        // As many entries as allowed, then as many head updates as still fit (usually all of them: one command in total).
        private (int Rows, int Heads) NextChunk(int remainingRows, int remainingHeads)
        {
            var rows = Math.Min(MaxRowsPerCommand, remainingRows);
            var room = _maxParameters - rows * _logParameters.Length;
            return (rows, Math.Min(remainingHeads, room / _headParameters.Length));
        }

        private (IRelationalCommandTemplate Template, Dictionary<string, object?> Values) Prepare(
            DbContext context, IReadOnlyList<AuditLog> logs, int offset, int rows, IReadOnlyList<AuditChainState> heads, int headOffset, int headCount)
        {
            var command = _appendCommands.GetOrAdd((rows, headCount), BuildAppend);
            var values = new Dictionary<string, object?>(rows * _logParameters.Length + headCount * _headParameters.Length);
            var index = 0;

            for (var row = 0; row < rows; row++)
            {
                var log = logs[offset + row];
                foreach (var get in AuditSqlCommands.LogGetters)
                {
                    values[_parameterNames[index++]] = get(log);
                }
            }

            for (var i = 0; i < headCount; i++)
            {
                var head = heads[headOffset + i];
                values[_parameterNames[index++]] = head.LastHash;
                values[_parameterNames[index++]] = head.UnanchoredCount;
                values[_parameterNames[index++]] = head.LastModified;
                values[_parameterNames[index++]] = head.LastSequence;
                values[_parameterNames[index++]] = head.KeyId;
                values[_parameterNames[index++]] = head.Mac;
                values[_parameterNames[index++]] = head.TableName;
            }

            return (command, values);
        }

        // Every inserted row and every head update counts one affected row. -1 means the server does not report counts
        // (SET NOCOUNT ON); then the check is left to the unique index and the head MAC.
        private static void Check(int affected, int rows, IReadOnlyList<AuditChainState> heads, int headOffset, int headCount)
        {
            var expected = rows + headCount;
            if (affected >= 0 && affected != expected)
            {
                var tables = string.Join(", ", heads.Skip(headOffset).Take(headCount).Select(h => h.TableName));
                throw new InvalidOperationException(
                    $"Writing the audit trail affected {affected} rows instead of {expected}: a chain head of table(s) {tables} " +
                    "was removed while it was locked.");
            }
        }

        private IRelationalCommandTemplate BuildAppend((int Rows, int Heads) shape)
        {
            var sql = new StringBuilder(_sql.InsertLogsPrefix.Length + shape.Rows * _logParameters.Length * 6 + shape.Heads * 256);
            var parameters = new List<(RelationalTypeMapping, bool)>(shape.Rows * _logParameters.Length + shape.Heads * _headParameters.Length);
            var index = 0;

            sql.Append(_sql.InsertLogsPrefix);
            for (var row = 0; row < shape.Rows; row++)
            {
                sql.Append(row == 0 ? "(" : ", (");
                for (var column = 0; column < _logParameters.Length; column++)
                {
                    sql.Append(column == 0 ? string.Empty : ", ").Append(Placeholder(index++));
                    parameters.Add(_logParameters[column]);
                }

                sql.Append(')');
            }

            for (var head = 0; head < shape.Heads; head++)
            {
                sql.Append(_helper.StatementTerminator).AppendLine();
                var names = Enumerable.Range(index, _headParameters.Length).Select(i => (object)Placeholder(i)).ToArray();
                sql.Append(string.Format(CultureInfo.InvariantCulture, _sql.UpdateChainState, names));
                parameters.AddRange(_headParameters);
                index += _headParameters.Length;
            }

            return Build(sql.ToString(), parameters);
        }

        #endregion

        private IRelationalCommandTemplate Build(string sql, IReadOnlyList<(RelationalTypeMapping Mapping, bool Nullable)> parameters)
        {
            var builder = _factory.Create().Append(sql);
            for (var i = 0; i < parameters.Count; i++)
            {
                builder.AddParameter(_parameterNames[i], _helper.GenerateParameterName(_parameterNames[i]), parameters[i].Mapping, parameters[i].Nullable);
            }

            return builder.Build();
        }

        private string Placeholder(int index) => _helper.GenerateParameterNamePlaceholder(_parameterNames[index]);

        private static (IRelationalConnection Connection, IRelationalCommand Command) Rent(DbContext context, IRelationalCommandTemplate template)
        {
            var connection = context.GetService<IRelationalConnection>();
            var command = connection.RentCommand();
            command.PopulateFrom(template);
            return (connection, command);
        }

        private static RelationalCommandParameterObject Parameters(
            DbContext context, IRelationalConnection connection, IReadOnlyDictionary<string, object?> values) => new(
            connection,
            values,
            null,
            context,
            context.GetService<IRelationalCommandDiagnosticsLogger>(),
            CommandSource.SaveChanges);

        private static (RelationalTypeMapping Mapping, bool Nullable) Mapping(IEntityType entityType, string propertyName)
        {
            var property = entityType.FindProperty(propertyName)!;
            return (property.GetRelationalTypeMapping(), property.IsNullable);
        }
    }
}
