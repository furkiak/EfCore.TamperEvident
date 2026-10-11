using EfCore.TamperEvident.Models;

namespace EfCore.TamperEvident.Services
{
    /// <summary>
    /// Publishes chain head snapshots (anchors) to a location outside of the audited database.
    /// Implement <see cref="PublishAsync"/>; implementations written for 1.x that only implement
    /// <see cref="SendAnchorAsync"/> keep working.
    /// </summary>
    public interface IAnchorPublisher
    {
        /// <summary>
        /// Publishes an anchor. Throw to signal a failure; delivery is retried according to
        /// <see cref="Configuration.TamperEvidentOptions.AnchorMaxAttempts"/>.
        /// </summary>
        /// <param name="anchor">The anchor to publish.</param>
        /// <param name="cancellationToken">A token to cancel the delivery.</param>
        Task PublishAsync(AuditAnchor anchor, CancellationToken cancellationToken = default)
#pragma warning disable CS0618 // the default implementation bridges to the 1.x member on purpose
            => SendAnchorAsync(anchor.TableName, anchor.Hash, anchor.RecordCount);
#pragma warning restore CS0618

        /// <summary>The 1.x publishing member, kept for source compatibility.</summary>
        /// <param name="tableName">The audited table.</param>
        /// <param name="currentHash">The anchor hash.</param>
        /// <param name="recordCount">How many entries the anchor covers.</param>
        [Obsolete("Implement PublishAsync(AuditAnchor, CancellationToken) instead.")]
        Task SendAnchorAsync(string tableName, string currentHash, int recordCount)
            => throw new NotImplementedException($"{GetType().Name} must implement {nameof(PublishAsync)}.");
    }
}
