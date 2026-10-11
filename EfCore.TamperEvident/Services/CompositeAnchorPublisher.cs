using EfCore.TamperEvident.Models;

namespace EfCore.TamperEvident.Services
{
    /// <summary>
    /// Publishes every anchor to several publishers, for example an e-mail and a webhook. The publishers are
    /// retried independently of each other, so a failing one never causes duplicates at the others.
    /// </summary>
    public sealed class CompositeAnchorPublisher : IAnchorPublisher
    {
        /// <summary>Creates the composite.</summary>
        /// <param name="publishers">The publishers that receive every anchor.</param>
        public CompositeAnchorPublisher(params IAnchorPublisher[] publishers)
        {
            ArgumentNullException.ThrowIfNull(publishers);
            Publishers = publishers.ToArray();
        }

        /// <summary>The wrapped publishers.</summary>
        public IReadOnlyList<IAnchorPublisher> Publishers { get; }

        /// <inheritdoc />
        public async Task PublishAsync(AuditAnchor anchor, CancellationToken cancellationToken = default)
        {
            var failures = new List<Exception>();
            foreach (var publisher in Publishers)
            {
                try
                {
                    await publisher.PublishAsync(anchor, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    failures.Add(ex);
                }
            }

            if (failures.Count > 0)
            {
                throw new AggregateException("One or more anchor publishers failed.", failures);
            }
        }
    }
}
