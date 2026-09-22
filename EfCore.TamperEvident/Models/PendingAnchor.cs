using System.ComponentModel.DataAnnotations;

namespace EfCore.TamperEvident.Models;

public sealed class PendingAnchor
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string TableName { get; set; }
    public required string AnchorHash { get; set; }
    public int RecordCount { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? DeliveredAtUtc { get; set; }
    public int AttemptCount { get; set; }
    public string? LastError { get; set; }
}
