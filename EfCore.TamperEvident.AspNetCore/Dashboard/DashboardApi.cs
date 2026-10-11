using System.Globalization;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.TamperEvident.AspNetCore
{
    /// <summary>The JSON API behind the dashboard.</summary>
    internal sealed class DashboardApi<TContext>
        where TContext : DbContext
    {
        /// <summary>Header that the dashboard sends with every state changing request (a simple CSRF barrier).</summary>
        public const string RequestHeader = "X-Requested-With";

        public const string RequestHeaderValue = "tamper-evident";

        private readonly DashboardOptions _options;
        private readonly AuditVerificationState _fallbackState = new();
        private int _verificationRunning;

        public DashboardApi(DashboardOptions options)
        {
            _options = options;
        }

        public async Task<IResult> Overview(HttpContext http, CancellationToken cancellationToken)
        {
            var db = http.RequestServices.GetRequiredService<TContext>();
            var logs = db.Set<AuditLog>().AsNoTracking();

            var counts = await logs.GroupBy(l => l.TableName)
                .Select(g => new { Table = g.Key, Records = g.Count(), LastTicks = g.Max(l => l.TimestampTicks) })
                .ToListAsync(cancellationToken);
            var states = await db.Set<AuditChainState>().AsNoTracking().ToListAsync(cancellationToken);
            var users = await logs.Select(l => l.UserId).Distinct().CountAsync(cancellationToken);

            var names = counts.Select(c => c.Table).Union(states.Select(s => s.TableName), StringComparer.Ordinal).OrderBy(n => n, StringComparer.Ordinal);
            var tables = names.Select(name =>
            {
                var count = counts.FirstOrDefault(c => c.Table == name);
                var state = states.FirstOrDefault(s => s.TableName == name);
                return new TableDto(
                    name,
                    count?.Records ?? 0,
                    state?.LastSequence ?? 0,
                    state?.LastHash,
                    count is null ? null : new DateTime(count.LastTicks, DateTimeKind.Utc),
                    state?.UnanchoredCount ?? 0,
                    state?.Mac is not null);
            }).ToList();

            var latest = StateOf(http).Latest;
            return Json(new
            {
                generatedUtc = DateTimeOffset.UtcNow,
                version = DashboardAssets.Version,
                title = _options.Title,
                totals = new
                {
                    tables = tables.Count,
                    records = tables.Sum(t => t.Records),
                    users,
                    lastEntryUtc = tables.Max(t => t.LastEntryUtc)
                },
                tables,
                verification = latest is null ? null : ToDto(latest.Report, latest.Source),
                capabilities = new
                {
                    verify = ResolveAuditOptions(http) is not null,
                    export = _options.AllowExport
                }
            });
        }

        public async Task<IResult> Logs(HttpContext http, CancellationToken cancellationToken)
        {
            var db = http.RequestServices.GetRequiredService<TContext>();
            var query = ApplyFilters(db.AuditLogs(), http.Request.Query);

            var pageSize = Math.Clamp(IntOf(http.Request.Query["pageSize"], 50), 1, Math.Max(1, _options.MaxPageSize));
            var page = Math.Max(1, IntOf(http.Request.Query["page"], 1));

            var total = await query.CountAsync(cancellationToken);
            var items = await query.Newest()
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(l => new LogDto(
                    l.Id, l.TableName, l.RecordId, l.ActionType, l.UserId, new DateTime(l.TimestampTicks, DateTimeKind.Utc),
                    l.SequenceNumber, l.HashVersion, l.KeyId, l.PreviousHash, l.CurrentHash, l.OldValues, l.NewValues))
                .ToListAsync(cancellationToken);

            return Json(new { total, page, pageSize, items });
        }

        public static async Task<IResult> Activity(HttpContext http, CancellationToken cancellationToken)
        {
            var db = http.RequestServices.GetRequiredService<TContext>();
            var days = Math.Clamp(IntOf(http.Request.Query["days"], 14), 1, 90);
            var table = ((string?)http.Request.Query["table"]).NullIfBlank();

            var first = DateTime.UtcNow.Date.AddDays(-(days - 1));
            var firstTicks = first.Ticks;
            var logs = db.AuditLogs().Where(l => l.TimestampTicks >= firstTicks);
            if (table is not null)
            {
                logs = logs.ForTable(table);
            }

            var rows = await logs
                .GroupBy(l => new { Day = l.TimestampTicks / TimeSpan.TicksPerDay, l.ActionType })
                .Select(g => new { g.Key.Day, g.Key.ActionType, Count = g.Count() })
                .ToListAsync(cancellationToken);

            var series = Enumerable.Range(0, days).Select(offset =>
            {
                var date = first.AddDays(offset);
                var day = date.Ticks / TimeSpan.TicksPerDay;
                int Count(string action) => rows.Where(r => r.Day == day && r.ActionType == action).Sum(r => r.Count);
                return new
                {
                    date = date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                    added = Count(AuditActions.Added),
                    modified = Count(AuditActions.Modified),
                    deleted = Count(AuditActions.Deleted),
                    softDelete = Count(AuditActions.SoftDelete),
                    restored = Count(AuditActions.Restored)
                };
            }).ToList();

            return Json(new { days, series });
        }

        public async Task<IResult> Verify(HttpContext http, VerifyRequest? request, CancellationToken cancellationToken)
        {
            if (!http.Request.Headers.TryGetValue(RequestHeader, out var header) || header != RequestHeaderValue)
            {
                return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Missing request header",
                    detail: $"{RequestHeader}: {RequestHeaderValue} is required.");
            }

            var auditOptions = ResolveAuditOptions(http);
            if (auditOptions is null)
            {
                return Results.Problem(statusCode: StatusCodes.Status501NotImplemented, title: "Verification is not configured",
                    detail: "Register the secret key with services.AddTamperEvident(...) or set DashboardOptions.AuditOptions.");
            }

            // Verifying reads every entry: refuse to run several verifications at the same time.
            if (Interlocked.CompareExchange(ref _verificationRunning, 1, 0) != 0)
            {
                return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "A verification is already running");
            }

            try
            {
                var db = http.RequestServices.GetRequiredService<TContext>();
                var verifier = new AuditVerifier(db, auditOptions);
                var table = string.IsNullOrWhiteSpace(request?.Table) ? null : request!.Table!.Trim();
                var pasted = AnchorSources.ExtractHashes(request?.Anchors);

                AuditVerificationReport report;
                if (table is not null)
                {
                    var single = await verifier.VerifyTableIntegrityAsync(table, pasted.Concat(await StoredAnchorsAsync(http, table, cancellationToken)), cancellationToken);
                    report = new AuditVerificationReport
                    {
                        IsValid = single.IsValid,
                        Message = single.Message,
                        Tables = new[] { single },
                        CompletedUtc = DateTimeOffset.UtcNow
                    };
                }
                else
                {
                    report = await VerifyEverythingAsync(http, db, verifier, pasted, cancellationToken);
                }

                StateOf(http).Update(report, "manual");
                return Json(ToDto(report, "manual"));
            }
            finally
            {
                Volatile.Write(ref _verificationRunning, 0);
            }
        }

        public async Task<IResult> Export(HttpContext http, CancellationToken cancellationToken)
        {
            if (!_options.AllowExport)
            {
                return Results.NotFound();
            }

            var query = http.Request.Query;
            var format = ((string?)query["format"] ?? "csv").ToLowerInvariant();
            var table = ((string?)query["table"]).NullIfBlank();
            var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            var baseName = "tamper-evident-" + Sanitize(table ?? "all") + "-" + stamp;
            var db = http.RequestServices.GetRequiredService<TContext>();

            switch (format)
            {
                case "csv":
                    return Results.Stream(
                        stream => AuditExporter.WriteCsvAsync(stream, ApplyFilters(db.AuditLogs(), query).InChainOrder(), cancellationToken),
                        "text/csv; charset=utf-8", baseName + ".csv");
                case "jsonl":
                    return Results.Stream(
                        stream => AuditExporter.WriteJsonLinesAsync(stream, ApplyFilters(db.AuditLogs(), query).InChainOrder(), cancellationToken),
                        "application/x-ndjson", baseName + ".jsonl");
                case "evidence":
                    var auditOptions = ResolveAuditOptions(http);
                    if (auditOptions is null)
                    {
                        return Results.Problem(statusCode: StatusCodes.Status501NotImplemented, title: "Verification is not configured");
                    }

                    var anchors = _options.AnchorProvider is { } provider
                        ? await provider(http.RequestServices, cancellationToken)
                        : null;
                    return Results.Stream(
                        stream => AuditExporter.WriteEvidenceBundleAsync(stream, db, new AuditVerifier(db, auditOptions), table, anchors, cancellationToken),
                        "application/json", baseName + "-evidence.json");
                default:
                    return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Unknown format", detail: "Use csv, jsonl or evidence.");
            }
        }

        private async Task<AuditVerificationReport> VerifyEverythingAsync(
            HttpContext http, TContext db, AuditVerifier verifier, IReadOnlyList<string> pasted, CancellationToken cancellationToken)
        {
            var stored = _options.AnchorProvider is { } provider
                ? await provider(http.RequestServices, cancellationToken)
                : null;
            var perTable = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            if (stored is not null)
            {
                foreach (var (name, hashes) in stored)
                {
                    perTable[name] = hashes.ToList();
                }
            }

            // Pasted anchors do not say which table they belong to: find out where each of them occurs.
            var unmatched = new List<string>(pasted);
            foreach (var chunk in pasted.Chunk(500))
            {
                var found = await db.AuditLogs().Where(l => chunk.Contains(l.CurrentHash))
                    .Select(l => new { l.TableName, l.CurrentHash }).ToListAsync(cancellationToken);
                foreach (var hit in found)
                {
                    if (!perTable.TryGetValue(hit.TableName, out var list))
                    {
                        perTable[hit.TableName] = list = new List<string>();
                    }

                    list.Add(hit.CurrentHash);
                    unmatched.Remove(hit.CurrentHash);
                }
            }

            var report = await verifier.VerifyAllAsync(
                perTable.ToDictionary(p => p.Key, p => (IEnumerable<string>)p.Value, StringComparer.Ordinal), cancellationToken);

            if (unmatched.Count == 0)
            {
                return report;
            }

            var mismatch = new AuditVerificationResult
            {
                IsValid = false,
                Failure = AuditFailureKind.AnchorMismatch,
                TableName = null,
                Message = $"ANCHOR MISMATCH! {unmatched.Count} of the provided anchor keys were not found in any audited table. " +
                          "The database history has likely been regenerated (Hash Recalculation Attack)."
            };
            return new AuditVerificationReport
            {
                IsValid = false,
                Message = mismatch.Message,
                Tables = report.Tables.Append(mismatch).ToList(),
                CompletedUtc = DateTimeOffset.UtcNow
            };
        }

        private async Task<IEnumerable<string>> StoredAnchorsAsync(HttpContext http, string table, CancellationToken cancellationToken)
        {
            if (_options.AnchorProvider is not { } provider)
            {
                return Array.Empty<string>();
            }

            var stored = await provider(http.RequestServices, cancellationToken);
            return stored is not null && stored.TryGetValue(table, out var hashes) ? hashes : Array.Empty<string>();
        }

        private TamperEvidentOptions? ResolveAuditOptions(HttpContext http) =>
            _options.AuditOptions ?? http.RequestServices.GetService<TamperEvidentOptions>();

        private AuditVerificationState StateOf(HttpContext http) =>
            http.RequestServices.GetService<AuditVerificationState>() ?? _fallbackState;

        private static IQueryable<AuditLog> ApplyFilters(IQueryable<AuditLog> logs, IQueryCollection query)
        {
            if (((string?)query["table"]).NullIfBlank() is { } table)
            {
                logs = logs.ForTable(table);
            }

            if (((string?)query["recordId"]).NullIfBlank() is { } recordId)
            {
                logs = logs.Where(l => l.RecordId == recordId);
            }

            if (((string?)query["user"]).NullIfBlank() is { } user)
            {
                logs = logs.ByUser(user);
            }

            if (((string?)query["action"]).NullIfBlank() is { } action)
            {
                var actions = action.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                logs = logs.Where(l => actions.Contains(l.ActionType));
            }

            logs = logs.Between(DateOf(query["from"]), DateOf(query["to"]));

            if (LongOf(query["seqFrom"]) is { } sequenceFrom)
            {
                logs = logs.Where(l => l.SequenceNumber >= sequenceFrom);
            }

            if (LongOf(query["seqTo"]) is { } sequenceTo)
            {
                logs = logs.Where(l => l.SequenceNumber <= sequenceTo);
            }

            if (((string?)query["q"]).NullIfBlank() is { } text)
            {
                logs = logs.Where(l =>
                    l.RecordId == text || l.UserId == text || l.TableName == text || l.CurrentHash.StartsWith(text));
            }

            return logs;
        }

        private static DateTimeOffset? DateOf(string? value) =>
            DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed) ? parsed : null;

        private static long? LongOf(string? value) =>
            long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;

        private static int IntOf(string? value, int fallback) =>
            int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : fallback;

        private static string Sanitize(string name) =>
            new string(name.Select(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' ? c : '_').ToArray());

        private static IResult Json(object value) => Results.Json(value, statusCode: StatusCodes.Status200OK);

        private static VerificationDto ToDto(AuditVerificationReport report, string source) => new(
            report.IsValid, report.Message, report.CompletedUtc, report.RecordsChecked, source,
            report.Tables.Select(t => new TableResultDto(
                t.TableName, t.IsValid, t.Failure.ToString(), t.Message, t.RecordsChecked, t.AnchorsMatched,
                t.FailedRecordId, t.FailedSequence, t.HeadHash, t.HeadSequence, Math.Round(t.Duration.TotalMilliseconds, 1))).ToList());

        internal sealed record VerifyRequest(string? Table, string? Anchors);

        private sealed record TableDto(
            string Table, int Records, long LastSequence, string? HeadHash, DateTime? LastEntryUtc, int UnanchoredCount, bool HeadAuthenticated);

        private sealed record LogDto(
            Guid Id, string Table, string RecordId, string Action, string UserId, DateTime TimestampUtc, long Sequence, int HashVersion,
            string? KeyId, string PreviousHash, string CurrentHash, string? OldValues, string? NewValues);

        private sealed record VerificationDto(
            bool IsValid, string Message, DateTimeOffset CompletedUtc, long RecordsChecked, string Source, List<TableResultDto> Tables);

        private sealed record TableResultDto(
            string? Table, bool IsValid, string Failure, string Message, long RecordsChecked, int AnchorsMatched,
            Guid? FailedRecordId, long? FailedSequence, string? HeadHash, long HeadSequence, double DurationMs);
    }

    internal static class StringExtensions
    {
        public static string? NullIfBlank(this string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}
