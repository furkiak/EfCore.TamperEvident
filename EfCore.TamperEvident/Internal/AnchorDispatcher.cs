using System.Collections.Concurrent;
using System.Diagnostics;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Diagnostics;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.Extensions.Logging;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// Delivers anchors after the audited transaction committed: in the background with retries,
    /// or inline when <see cref="TamperEvidentOptions.AwaitAnchorDelivery"/> is set.
    /// </summary>
    internal sealed class AnchorDispatcher
    {
        private readonly TamperEvidentOptions _options;
        private readonly ConcurrentDictionary<Task, byte> _inFlight = new();
        private IAnchorPublisher? _publisher;
        private bool _resolved;

        public AnchorDispatcher(TamperEvidentOptions options)
        {
            _options = options;
        }

        /// <summary>Whether anchors are produced and a publisher is configured to receive them.</summary>
        public bool IsEnabled =>
            _options.AnchorThreshold > 0
            && (_options.CustomAnchorPublisher is not null || SmtpAnchorPublisher.IsConfigured(_options));

        /// <param name="anchors">The anchors to deliver.</param>
        /// <param name="logger">
        /// A logger that was created while the <c>DbContext</c> was still alive. The logger factory of a context is
        /// disposed together with it, so delivery that happens later must not create loggers itself.
        /// </param>
        /// <param name="cancellationToken">A token that cancels inline delivery.</param>
        public Task DispatchAsync(IReadOnlyList<AuditAnchor> anchors, ILogger? logger, CancellationToken cancellationToken)
        {
            var publisher = ResolvePublisher();
            if (publisher is null || anchors.Count == 0)
            {
                return Task.CompletedTask;
            }

            if (_options.AwaitAnchorDelivery)
            {
                return DeliverAllAsync(publisher, anchors, logger, cancellationToken);
            }

            var task = Task.Run(() => DeliverAllAsync(publisher, anchors, logger, CancellationToken.None), CancellationToken.None);
            _inFlight[task] = 0;
            _ = task.ContinueWith(static (t, state) => ((ConcurrentDictionary<Task, byte>)state!).TryRemove(t, out _), _inFlight, TaskScheduler.Default);
            return Task.CompletedTask;
        }

        /// <summary>Waits until all background deliveries finished, for example before the application exits.</summary>
        public async Task FlushAsync(CancellationToken cancellationToken)
        {
            while (!_inFlight.IsEmpty)
            {
                var pending = _inFlight.Keys.ToArray();
                await Task.WhenAll(pending).WaitAsync(cancellationToken).ConfigureAwait(false);
                foreach (var task in pending)
                {
                    _inFlight.TryRemove(task, out _);
                }
            }
        }

        private IAnchorPublisher? ResolvePublisher()
        {
            if (_resolved)
            {
                return _publisher;
            }

            _publisher = _options.CustomAnchorPublisher
                ?? (SmtpAnchorPublisher.IsConfigured(_options) ? new SmtpAnchorPublisher(_options, _options.LoggerFactory) : null);
            _resolved = true;
            return _publisher;
        }

        private async Task DeliverAllAsync(IAnchorPublisher publisher, IReadOnlyList<AuditAnchor> anchors, ILogger? logger, CancellationToken cancellationToken)
        {
            // A composite is flattened so that every target is retried on its own.
            var targets = publisher is CompositeAnchorPublisher composite ? composite.Publishers : new[] { publisher };

            var deliveries = new List<Task>();
            foreach (var anchor in anchors)
            {
                foreach (var target in targets)
                {
                    deliveries.Add(DeliverAsync(target, anchor, logger, cancellationToken));
                }
            }

            await Task.WhenAll(deliveries).ConfigureAwait(false);
        }

        private static void Count(AuditAnchor anchor, string result) => TamperEvidentTelemetry.AnchorsPublished.Add(1,
            new KeyValuePair<string, object?>(TamperEvidentTelemetry.Tags.Table, anchor.TableName),
            new KeyValuePair<string, object?>(TamperEvidentTelemetry.Tags.Result, result));

        private async Task DeliverAsync(IAnchorPublisher publisher, AuditAnchor anchor, ILogger? logger, CancellationToken cancellationToken)
        {
            var delay = _options.AnchorRetryDelay;
            using var activity = TamperEvidentTelemetry.Source.StartActivity(TamperEvidentTelemetry.Activities.PublishAnchor);
            activity?.SetTag(TamperEvidentTelemetry.Tags.Table, anchor.TableName);
            activity?.SetTag("tamper_evident.publisher", publisher.GetType().Name);
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    await publisher.PublishAsync(anchor, cancellationToken).ConfigureAwait(false);
                    Count(anchor, "success");
                    return;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    if (attempt >= _options.AnchorMaxAttempts)
                    {
                        Count(anchor, "failure");
                        activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                        logger?.LogError(ex, "Giving up delivering the anchor of table {TableName} (sequence {Sequence}) after {Attempts} attempts.",
                            anchor.TableName, anchor.SequenceNumber, attempt);

                        // The audited transaction is committed already, so a failing publisher must never fail SaveChanges.
                        return;
                    }

                    logger?.LogWarning(ex, "Delivering the anchor of table {TableName} failed (attempt {Attempt}); retrying in {Delay}.",
                        anchor.TableName, attempt, delay);
                    if (delay > TimeSpan.Zero)
                    {
                        await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                    }

                    delay += delay;
                }
            }
        }
    }
}
