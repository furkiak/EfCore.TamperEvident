using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace EfCore.TamperEvident.Services;

/// <summary>
/// Delivers durable anchors after the business transaction has committed.
/// Run periodically with a fresh DbContext. Delivery is at-least-once.
/// </summary>
public sealed class AnchorDispatcher
{
    private readonly DbContext _context;
    private readonly IAnchorPublisher _publisher;
    private readonly ILogger<AnchorDispatcher>? _logger;

    public AnchorDispatcher(DbContext context, TamperEvidentOptions options)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        options = options ?? throw new ArgumentNullException(nameof(options));
        options.Validate();
        _publisher = options.CustomAnchorPublisher ?? new SmtpAnchorPublisher(options, options.LoggerFactory);
        _logger = options.LoggerFactory?.CreateLogger<AnchorDispatcher>();
    }

    public async Task<int> DispatchPendingAsync(int batchSize = 100, CancellationToken cancellationToken = default)
    {
        if (batchSize is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(batchSize));
        var pending = await _context.Set<PendingAnchor>()
            .Where(x => x.DeliveredAtUtc == null)
            .OrderBy(x => x.CreatedAtUtc).ThenBy(x => x.Id)
            .Take(batchSize).ToListAsync(cancellationToken);
        var delivered = 0;
        foreach (var anchor in pending)
        {
            cancellationToken.ThrowIfCancellationRequested();
            anchor.AttemptCount++;
            try
            {
                await _publisher.SendAnchorAsync(new AnchorDelivery(anchor.Id, anchor.TableName,
                    anchor.AnchorHash, anchor.RecordCount, anchor.CreatedAtUtc), cancellationToken);
                anchor.DeliveredAtUtc = DateTime.UtcNow;
                anchor.LastError = null;
                await _context.SaveChangesAsync(cancellationToken);
                delivered++;
                _logger?.LogInformation("Anchor {AnchorId} accepted by publisher on attempt {AttemptCount}.", anchor.Id, anchor.AttemptCount);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                anchor.DeliveredAtUtc = null;
                anchor.LastError = ex.GetType().Name;
                await _context.SaveChangesAsync(cancellationToken);
                _logger?.LogWarning("Anchor {AnchorId} remains pending after attempt {AttemptCount}: {ErrorType}.",
                    anchor.Id, anchor.AttemptCount, anchor.LastError);
            }
        }
        return delivered;
    }
}
