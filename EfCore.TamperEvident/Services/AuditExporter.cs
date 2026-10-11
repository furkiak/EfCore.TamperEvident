using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Internal;
using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Services
{
    /// <summary>
    /// Exports the audit trail, for auditors, legal proceedings and archives.
    /// </summary>
    public static class AuditExporter
    {
        private static readonly System.Buffers.SearchValues<char> CsvSpecialCharacters = System.Buffers.SearchValues.Create(",\"\r\n");

        private static readonly string[] CsvHeader =
        {
            "Id", "TableName", "RecordId", "ActionType", "UserId", "TimestampUtc", "SequenceNumber",
            "HashVersion", "KeyId", "PreviousHash", "CurrentHash", "OldValues", "NewValues", "Metadata"
        };

        /// <summary>The version of the evidence bundle format written by <see cref="WriteEvidenceBundleAsync"/>.</summary>
        public const int EvidenceFormat = 2;

        /// <summary>Writes one JSON object per line (JSON Lines), streamed.</summary>
        /// <param name="output">The destination.</param>
        /// <param name="logs">The entries to export.</param>
        /// <param name="cancellationToken">A token to cancel the export.</param>
        public static async Task WriteJsonLinesAsync(Stream output, IQueryable<AuditLog> logs, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(output);
            ArgumentNullException.ThrowIfNull(logs);

            await using var writer = new StreamWriter(output, new UTF8Encoding(false), 4096, leaveOpen: true);
            await foreach (var log in logs.AsNoTracking().AsAsyncEnumerable().WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                await writer.WriteLineAsync(JsonSerializer.Serialize(EvidenceRecord.From(log), EvidenceRecord.Json)).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Writes RFC 4180 CSV, streamed. Cells that a spreadsheet could interpret as a formula
        /// (starting with <c>=</c>, <c>+</c>, <c>-</c> or <c>@</c>) are prefixed with an apostrophe.
        /// </summary>
        /// <param name="output">The destination.</param>
        /// <param name="logs">The entries to export.</param>
        /// <param name="cancellationToken">A token to cancel the export.</param>
        public static async Task WriteCsvAsync(Stream output, IQueryable<AuditLog> logs, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(output);
            ArgumentNullException.ThrowIfNull(logs);

            await using var writer = new StreamWriter(output, new UTF8Encoding(false), 4096, leaveOpen: true) { NewLine = "\r\n" };
            await writer.WriteLineAsync(string.Join(",", CsvHeader)).ConfigureAwait(false);

            await foreach (var log in logs.AsNoTracking().AsAsyncEnumerable().WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                var cells = new[]
                {
                    log.Id.ToString(), log.TableName, log.RecordId, log.ActionType, log.UserId,
                    log.TimestampUtc.ToString("O", CultureInfo.InvariantCulture),
                    log.SequenceNumber.ToString(CultureInfo.InvariantCulture),
                    log.HashVersion.ToString(CultureInfo.InvariantCulture),
                    log.KeyId ?? string.Empty, log.PreviousHash, log.CurrentHash,
                    log.OldValues ?? string.Empty, log.NewValues ?? string.Empty, log.Metadata ?? string.Empty
                };
                await writer.WriteLineAsync(string.Join(",", cells.Select(Csv))).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Writes an evidence bundle: for every table the signed chain head, the verification result and all entries in
        /// chain order, plus when and by which library version it was produced. Hand it to an auditor together with the
        /// anchors that were received outside of the database: <see cref="AuditEvidence.VerifyBundleAsync"/> (or the
        /// <c>tamper-evident verify</c> command) checks it again without access to the database.
        /// </summary>
        /// <param name="output">The destination.</param>
        /// <param name="context">The context that stores the audit trail.</param>
        /// <param name="verifier">The verifier that vouches for the entries.</param>
        /// <param name="tableName">A single table, or <c>null</c> for all audited tables.</param>
        /// <param name="anchors">Externally stored anchor hashes per table (optional).</param>
        /// <param name="cancellationToken">A token to cancel the export.</param>
        public static async Task WriteEvidenceBundleAsync(
            Stream output,
            DbContext context,
            AuditVerifier verifier,
            string? tableName = null,
            IReadOnlyDictionary<string, IEnumerable<string>>? anchors = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(output);
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(verifier);

            var tables = tableName is null
                ? await verifier.GetAuditedTablesAsync(cancellationToken).ConfigureAwait(false)
                : new[] { tableName };

            // A Utf8JsonWriter that targets a Stream flushes synchronously when its buffer fills up, which web servers
            // forbid. It writes into memory instead and the buffer is copied to the stream asynchronously.
            var buffer = new System.Buffers.ArrayBufferWriter<byte>(16 * 1024);
            using var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true });

            async Task DrainAsync(bool force)
            {
                if (!force && writer.BytesPending + buffer.WrittenCount < 32 * 1024)
                {
                    return;
                }

                writer.Flush();
                await output.WriteAsync(buffer.WrittenMemory, cancellationToken).ConfigureAwait(false);
                buffer.Clear();
            }

            writer.WriteStartObject();
            writer.WriteNumber("format", EvidenceFormat);
            writer.WriteString("generatedUtc", DateTimeOffset.UtcNow);
            writer.WriteString("generator", "EfCore.TamperEvident " + (typeof(AuditExporter).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "2"));
            writer.WriteStartArray("tables");

            foreach (var table in tables)
            {
                IEnumerable<string>? tableAnchors = null;
                anchors?.TryGetValue(table, out tableAnchors);
                // The head is read first and only the entries it covers are written, so the bundle is a consistent
                // snapshot even while new entries are appended.
                var head = await context.Set<AuditChainState>().AsNoTracking()
                    .FirstOrDefaultAsync(s => s.TableName == table, cancellationToken).ConfigureAwait(false);
                var verification = await verifier.VerifyTableIntegrityAsync(table, tableAnchors, cancellationToken).ConfigureAwait(false);

                writer.WriteStartObject();
                writer.WriteString("table", table);
                if (head is null)
                {
                    writer.WriteNull("head");
                }
                else
                {
                    writer.WritePropertyName("head");
                    JsonSerializer.Serialize(writer, EvidenceHead.From(head), EvidenceRecord.Json);
                }

                writer.WriteStartObject("verification");
                writer.WriteBoolean("isValid", verification.IsValid);
                writer.WriteString("result", verification.Failure.ToString());
                writer.WriteString("message", verification.Message);
                writer.WriteNumber("recordsChecked", verification.RecordsChecked);
                writer.WriteNumber("anchorsMatched", verification.AnchorsMatched);
                writer.WriteString("headHash", verification.HeadHash);
                writer.WriteNumber("headSequence", verification.HeadSequence);
                writer.WriteNumber("redactedRecords", verification.RedactedRecords);
                writer.WriteEndObject();

                writer.WriteStartArray("records");
                var query = context.AuditLogs().ForTable(table);
                if (head is not null)
                {
                    var last = head.LastSequence;
                    query = query.Where(x => x.SequenceNumber <= last);
                }

                await foreach (var log in query.OrderBy(x => x.SequenceNumber).ThenBy(x => x.TimestampTicks)
                    .AsAsyncEnumerable().WithCancellation(cancellationToken).ConfigureAwait(false))
                {
                    JsonSerializer.Serialize(writer, EvidenceRecord.From(log), EvidenceRecord.Json);
                    await DrainAsync(force: false).ConfigureAwait(false);
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
            await DrainAsync(force: true).ConfigureAwait(false);
        }

        private static string Csv(string value)
        {
            if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
            {
                value = "'" + value;
            }

            return value.AsSpan().IndexOfAny(CsvSpecialCharacters) >= 0
                ? "\"" + value.Replace("\"", "\"\"") + "\""
                : value;
        }
    }
}
