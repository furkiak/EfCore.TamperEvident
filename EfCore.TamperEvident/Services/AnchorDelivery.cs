namespace EfCore.TamperEvident.Services;

/// <summary>A stable outbox identity and payload for at-least-once delivery.</summary>
public sealed record AnchorDelivery(
    Guid Id, string TableName, string AnchorHash, int RecordCount, DateTime CreatedAtUtc);
