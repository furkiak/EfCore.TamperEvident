using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace EfCore.TamperEvident.AspNetCore
{
    /// <summary>
    /// Verifies the whole audit trail on a schedule and reports tampering.
    /// </summary>
    /// <typeparam name="TContext">The context that stores the audit trail.</typeparam>
    public sealed class TamperEvidentVerificationService<TContext> : BackgroundService
        where TContext : DbContext
    {
        private readonly IServiceProvider _services;
        private readonly TamperEvidentVerificationOptions _options;
        private readonly AuditVerificationState _state;
        private readonly ILogger<TamperEvidentVerificationService<TContext>> _logger;

        /// <summary>Creates the service. It is normally registered with <c>AddTamperEvidentVerification</c>.</summary>
        /// <param name="services">The application services.</param>
        /// <param name="options">The schedule.</param>
        /// <param name="state">Where the results are stored.</param>
        /// <param name="logger">The logger.</param>
        public TamperEvidentVerificationService(
            IServiceProvider services,
            TamperEvidentVerificationOptions options,
            AuditVerificationState state,
            ILogger<TamperEvidentVerificationService<TContext>> logger)
        {
            _services = services;
            _options = options;
            _state = state;
            _logger = logger;
        }

        /// <summary>Runs one verification now. Used by the schedule and by tests.</summary>
        /// <param name="cancellationToken">A token to cancel the verification.</param>
        public async Task<AuditVerificationReport> VerifyOnceAsync(CancellationToken cancellationToken)
        {
            await using var scope = _services.CreateAsyncScope();
            var verifier = scope.ServiceProvider.GetRequiredService<AuditVerifier>();

            IReadOnlyDictionary<string, IEnumerable<string>>? anchors = null;
            if (_options.AnchorProvider is { } provider)
            {
                anchors = await provider(scope.ServiceProvider, cancellationToken).ConfigureAwait(false);
            }

            var checkpoints = _state.Checkpoints;
            var lastFull = _state.LastFullVerificationUtc;
            var full = !_options.Incremental
                || checkpoints is null
                || lastFull is null
                || DateTimeOffset.UtcNow - lastFull.Value >= _options.FullVerificationInterval;

            var report = await verifier.VerifyAllAsync(anchors, full ? null : checkpoints, cancellationToken).ConfigureAwait(false);
            _state.Update(report, "background");
            if (full)
            {
                _state.RecordFullVerification(report);
            }
            else
            {
                _state.RecordIncrementalVerification(report);
            }

            if (report.IsValid)
            {
                _logger.LogInformation("Audit trail verified ({Kind}): {Message} ({Records} entries).",
                    full ? "full" : "new entries", report.Message, report.RecordsChecked);
            }
            else
            {
                _logger.LogCritical("TAMPERING SUSPECTED in the audit trail: {Message}", report.Message);
                if (_options.OnTamperDetected is { } callback)
                {
                    try
                    {
                        await callback(report, scope.ServiceProvider, cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        _logger.LogError(ex, "The OnTamperDetected callback failed.");
                    }
                }
            }

            return report;
        }

        /// <inheritdoc />
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                if (_options.InitialDelay > TimeSpan.Zero)
                {
                    await Task.Delay(_options.InitialDelay, stoppingToken).ConfigureAwait(false);
                }

                using var timer = new PeriodicTimer(_options.Interval);
                do
                {
                    try
                    {
                        await VerifyOnceAsync(stoppingToken).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        // A failing verification (database down...) must not kill the schedule.
                        _logger.LogError(ex, "The scheduled verification of the audit trail failed.");
                    }
                }
                while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
            }
            catch (OperationCanceledException)
            {
                // The host is shutting down.
            }
        }
    }
}
