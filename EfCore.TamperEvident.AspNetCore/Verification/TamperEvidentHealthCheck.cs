using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace EfCore.TamperEvident.AspNetCore
{
    /// <summary>
    /// Reports the result of the latest verification: healthy while the chain is intact, unhealthy once tampering
    /// was detected, degraded when no recent verification exists.
    /// </summary>
    public sealed class TamperEvidentHealthCheck : IHealthCheck
    {
        private readonly AuditVerificationState _state;
        private readonly TamperEvidentVerificationOptions _options;

        /// <summary>Creates the health check.</summary>
        /// <param name="state">Where the verification results are stored.</param>
        /// <param name="options">The verification schedule, used to decide whether a result is stale.</param>
        public TamperEvidentHealthCheck(AuditVerificationState state, TamperEvidentVerificationOptions options)
        {
            _state = state;
            _options = options;
        }

        /// <inheritdoc />
        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            var latest = _state.Latest;
            if (latest is null)
            {
                return Task.FromResult(HealthCheckResult.Degraded("The audit trail has not been verified yet."));
            }

            var report = latest.Report;
            var data = new Dictionary<string, object>
            {
                ["completedUtc"] = report.CompletedUtc,
                ["tables"] = report.Tables.Count,
                ["records"] = report.RecordsChecked,
                ["source"] = latest.Source,
                ["incremental"] = report.Tables.Any(t => t.IsIncremental)
            };
            if (_state.LastFullVerificationUtc is { } lastFull)
            {
                data["lastFullVerificationUtc"] = lastFull;
            }

            if (!report.IsValid)
            {
                data["failedTables"] = string.Join(", ", report.Failures.Select(f => f.TableName));
                return Task.FromResult(new HealthCheckResult(context.Registration.FailureStatus, report.Message, data: data));
            }

            var age = DateTimeOffset.UtcNow - report.CompletedUtc;
            if (age > _options.Interval * 3 + TimeSpan.FromMinutes(5))
            {
                return Task.FromResult(HealthCheckResult.Degraded($"The last verification is {age.TotalMinutes:F0} minutes old.", data: data));
            }

            return Task.FromResult(HealthCheckResult.Healthy(report.Message, data));
        }
    }
}
