namespace EfCore.TamperEvident.Models
{
    /// <summary>
    /// A snapshot of a chain head that is published outside of the database.
    /// Because the anchor lives somewhere an attacker with database access cannot reach,
    /// rewriting the history of the table is detected during verification.
    /// </summary>
    /// <param name="TableName">The audited table.</param>
    /// <param name="Hash">The hash of the newest entry at the time the anchor was taken.</param>
    /// <param name="SequenceNumber">The sequence number of that entry.</param>
    /// <param name="RecordCount">How many entries were written since the previous anchor.</param>
    /// <param name="CreatedUtc">When the anchor was taken.</param>
    public sealed record AuditAnchor(
        string TableName,
        string Hash,
        long SequenceNumber,
        int RecordCount,
        DateTimeOffset CreatedUtc);
}
