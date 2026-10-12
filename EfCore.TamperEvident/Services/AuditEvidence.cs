using System.Diagnostics;
using System.Text.Json;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Internal;
using EfCore.TamperEvident.Models;

namespace EfCore.TamperEvident.Services
{
    /// <summary>
    /// Verifies evidence bundles (written by <see cref="AuditExporter.WriteEvidenceBundleAsync"/>) without access to the
    /// database: every hash is recomputed, every link followed, every redaction checked, the signed chain head compared with
    /// the newest entry and the anchors looked up. The bundle is streamed, so its size is not limited by memory.
    /// </summary>
    /// <remarks>
    /// The verdict that is stored in the bundle is ignored: only what can be recomputed counts. Verifying needs the
    /// secret key(s) the trail was sealed with, exactly like <see cref="AuditVerifier"/>.
    /// </remarks>
    public static class AuditEvidence
    {
        /// <summary>Verifies an evidence bundle.</summary>
        /// <param name="bundle">The bundle (JSON).</param>
        /// <param name="options">The options that hold the secret key(s).</param>
        /// <param name="anchors">Externally stored anchor hashes per table (optional).</param>
        /// <param name="cancellationToken">A token to cancel the verification.</param>
        /// <exception cref="InvalidDataException">The stream is not an evidence bundle of a supported format.</exception>
        public static async Task<AuditVerificationReport> VerifyBundleAsync(
            Stream bundle,
            TamperEvidentOptions options,
            IReadOnlyDictionary<string, IEnumerable<string>>? anchors = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(bundle);
            ArgumentNullException.ThrowIfNull(options);
            options.Validate();

            var keys = AuditKeyRing.Create(options);
            var results = new List<AuditVerificationResult>();
            using var reader = new JsonStreamReader(bundle);

            try
            {
                if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.TokenType != JsonTokenType.StartObject)
                {
                    throw new InvalidDataException("The evidence bundle is not a JSON object.");
                }

                var format = 0;
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) && reader.TokenType == JsonTokenType.PropertyName)
                {
                    var property = reader.String;
                    await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                    switch (property)
                    {
                        case "format" when reader.TokenType == JsonTokenType.Number:
                            format = JsonSerializer.Deserialize<int>((await reader.ReadValueAsync(cancellationToken).ConfigureAwait(false)).Span);
                            if (format != AuditExporter.EvidenceFormat)
                            {
                                throw new InvalidDataException($"Evidence bundles of format {format} are not supported (expected {AuditExporter.EvidenceFormat}).");
                            }

                            break;
                        case "tables" when reader.TokenType == JsonTokenType.StartArray:
                            if (format != AuditExporter.EvidenceFormat)
                            {
                                throw new InvalidDataException("The evidence bundle does not declare its format before its tables.");
                            }

                            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) && reader.TokenType == JsonTokenType.StartObject)
                            {
                                results.Add(await VerifyTableAsync(reader, keys, anchors, cancellationToken).ConfigureAwait(false));
                            }

                            break;
                        default:
                            await reader.SkipAsync(cancellationToken).ConfigureAwait(false);
                            break;
                    }
                }
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("The evidence bundle is not valid JSON: " + ex.Message, ex);
            }

            return AuditVerifier.Report(results);
        }

        /// <summary>
        /// Reads a bundle without verifying it: per table the number of entries, the time range, the users, the actions
        /// and the verdict stored at export time; and in which table each of <paramref name="locate"/> occurs.
        /// </summary>
        internal static async Task<EvidenceSummary> SummarizeAsync(Stream bundle, IReadOnlyCollection<string>? locate, CancellationToken cancellationToken)
        {
            var wanted = new HashSet<string>(locate ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            var summary = new EvidenceSummary();
            using var reader = new JsonStreamReader(bundle);

            try
            {
                if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.TokenType != JsonTokenType.StartObject)
                {
                    throw new InvalidDataException("The evidence bundle is not a JSON object.");
                }

                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) && reader.TokenType == JsonTokenType.PropertyName)
                {
                    var property = reader.String;
                    await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                    switch (property)
                    {
                        case "format":
                            summary.Format = JsonSerializer.Deserialize<int>((await reader.ReadValueAsync(cancellationToken).ConfigureAwait(false)).Span);
                            break;
                        case "generatedUtc":
                            summary.GeneratedUtc = DateTimeOffset.TryParse(reader.String, System.Globalization.CultureInfo.InvariantCulture,
                                System.Globalization.DateTimeStyles.AssumeUniversal, out var generated) ? generated : null;
                            break;
                        case "generator":
                            summary.Generator = reader.String;
                            break;
                        case "tables" when reader.TokenType == JsonTokenType.StartArray:
                            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) && reader.TokenType == JsonTokenType.StartObject)
                            {
                                summary.Tables.Add(await SummarizeTableAsync(reader, wanted, summary.Located, cancellationToken).ConfigureAwait(false));
                            }

                            break;
                        default:
                            await reader.SkipAsync(cancellationToken).ConfigureAwait(false);
                            break;
                    }
                }
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("The evidence bundle is not valid JSON: " + ex.Message, ex);
            }

            return summary;
        }

        private static async Task<EvidenceTableSummary> SummarizeTableAsync(
            JsonStreamReader reader, HashSet<string> wanted, Dictionary<string, string> located, CancellationToken cancellationToken)
        {
            var table = new EvidenceTableSummary();
            var users = new HashSet<string>(StringComparer.Ordinal);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) && reader.TokenType == JsonTokenType.PropertyName)
            {
                var property = reader.String;
                await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                switch (property)
                {
                    case "table":
                        table.Table = reader.String ?? string.Empty;
                        break;
                    case "head" when reader.TokenType == JsonTokenType.StartObject:
                        table.HeadSequence = JsonSerializer.Deserialize<EvidenceHead>(
                            (await reader.ReadValueAsync(cancellationToken).ConfigureAwait(false)).Span, EvidenceRecord.Json)?.LastSequence;
                        break;
                    case "verification" when reader.TokenType == JsonTokenType.StartObject:
                        using (var verdict = JsonDocument.Parse(await reader.ReadValueAsync(cancellationToken).ConfigureAwait(false)))
                        {
                            table.StoredResult = verdict.RootElement.TryGetProperty("result", out var result) ? result.GetString() : null;
                        }

                        break;
                    case "records" when reader.TokenType == JsonTokenType.StartArray:
                        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) && reader.TokenType == JsonTokenType.StartObject)
                        {
                            var record = JsonSerializer.Deserialize<EvidenceRecord>(
                                (await reader.ReadValueAsync(cancellationToken).ConfigureAwait(false)).Span, EvidenceRecord.Json)!;
                            var log = record.ToLog();
                            table.Entries++;
                            users.Add(log.UserId);
                            table.Actions[log.ActionType] = table.Actions.GetValueOrDefault(log.ActionType) + 1;
                            table.FirstEntryUtc ??= log.TimestampUtc;
                            table.LastEntryUtc = log.TimestampUtc;
                            if (wanted.Contains(log.CurrentHash))
                            {
                                located[log.CurrentHash.ToLowerInvariant()] = table.Table;
                            }
                        }

                        break;
                    default:
                        await reader.SkipAsync(cancellationToken).ConfigureAwait(false);
                        break;
                }
            }

            table.Users = users.Count;
            return table;
        }

        private static async Task<AuditVerificationResult> VerifyTableAsync(
            JsonStreamReader reader, AuditKeyRing keys, IReadOnlyDictionary<string, IEnumerable<string>>? anchors, CancellationToken cancellationToken)
        {
            var stopwatch = Stopwatch.StartNew();
            string? table = null;
            AuditChainState? head = null;
            var headSeen = false;
            ChainValidator? validator = null;
            ChainFailure? failure = null;

            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) && reader.TokenType == JsonTokenType.PropertyName)
            {
                var property = reader.String;
                await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                switch (property)
                {
                    case "table":
                        table = reader.String;
                        break;
                    case "head":
                        headSeen = true;
                        head = reader.TokenType == JsonTokenType.Null
                            ? null
                            : JsonSerializer.Deserialize<EvidenceHead>((await reader.ReadValueAsync(cancellationToken).ConfigureAwait(false)).Span, EvidenceRecord.Json)?.ToState();
                        break;
                    case "records" when reader.TokenType == JsonTokenType.StartArray:
                        if (table is null || !headSeen)
                        {
                            throw new InvalidDataException("A table of the evidence bundle lists its records before its name and head.");
                        }

                        IEnumerable<string>? tableAnchors = null;
                        anchors?.TryGetValue(table, out tableAnchors);
                        validator = new ChainValidator(table, keys, null, tableAnchors);

                        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) && reader.TokenType == JsonTokenType.StartObject)
                        {
                            var bytes = await reader.ReadValueAsync(cancellationToken).ConfigureAwait(false);
                            if (failure is not null)
                            {
                                continue;
                            }

                            var record = JsonSerializer.Deserialize<EvidenceRecord>(bytes.Span, EvidenceRecord.Json)
                                ?? throw new InvalidDataException("An entry of the evidence bundle is empty.");
                            var log = record.ToLog();
                            if (!string.Equals(log.TableName, table, StringComparison.Ordinal))
                            {
                                failure = new ChainFailure(AuditFailureKind.ChainBroken,
                                    $"CHAIN BROKEN! Record ID: {log.Id} of table '{log.TableName}' was placed into the chain of table '{table}'.", log.Id, log.SequenceNumber);
                                continue;
                            }

                            failure = validator.Accept(log);
                        }

                        break;
                    default:
                        await reader.SkipAsync(cancellationToken).ConfigureAwait(false);
                        break;
                }
            }

            if (table is null)
            {
                throw new InvalidDataException("A table of the evidence bundle has no name.");
            }

            validator ??= new ChainValidator(table, keys, null, null);
            failure ??= validator.CheckRedactions() ?? validator.CheckHead(head);
            if (failure is null && validator.UnmatchedAnchors.Count > 0)
            {
                failure = new ChainFailure(AuditFailureKind.AnchorMismatch,
                    "ANCHOR MISMATCH! The provided anchor keys were not found in the bundle. The history has likely been regenerated (Hash Recalculation Attack).");
            }

            return new AuditVerificationResult
            {
                IsValid = failure is null,
                Failure = failure?.Kind ?? AuditFailureKind.None,
                Message = failure?.Message ?? (validator.RecordsChecked == 0
                    ? "The bundle holds no entries for this table."
                    : "All verifications passed successfully! The hash chain is intact and matches its signed head."),
                TableName = table,
                RecordsChecked = validator.RecordsChecked,
                AnchorsMatched = validator.AnchorsMatched,
                RedactedRecords = validator.RedactedRecords,
                FailedRecordId = failure?.EntryId,
                FailedSequence = failure?.Sequence,
                HeadHash = validator.LastHash,
                HeadSequence = validator.Sequence,
                Duration = stopwatch.Elapsed
            };
        }
    }

    internal sealed class EvidenceSummary
    {
        public int Format { get; set; }

        public DateTimeOffset? GeneratedUtc { get; set; }

        public string? Generator { get; set; }

        public List<EvidenceTableSummary> Tables { get; } = new();

        /// <summary>Hash (lower case) to the table it occurs in.</summary>
        public Dictionary<string, string> Located { get; } = new(StringComparer.Ordinal);
    }

    internal sealed class EvidenceTableSummary
    {
        public string Table { get; set; } = string.Empty;

        public long Entries { get; set; }

        public long? HeadSequence { get; set; }

        public DateTime? FirstEntryUtc { get; set; }

        public DateTime? LastEntryUtc { get; set; }

        public int Users { get; set; }

        public SortedDictionary<string, long> Actions { get; } = new(StringComparer.Ordinal);

        public string? StoredResult { get; set; }
    }
}
