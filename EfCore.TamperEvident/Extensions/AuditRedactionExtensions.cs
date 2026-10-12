using EfCore.TamperEvident.Internal;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Extensions
{
    /// <summary>
    /// Redacts personal data from the audit trail (right to erasure under GDPR Art. 17 or KVKK Art. 7) without breaking
    /// the hash chain. See <see cref="AuditRedactionRequest"/> for how it works.
    /// </summary>
    public static class AuditRedactionExtensions
    {
        /// <summary>
        /// Redacts values from the audit entries of one entity.
        /// </summary>
        /// <param name="context">A context with the audit trail enabled.</param>
        /// <param name="entity">An entity of the audited model (it does not have to exist any more).</param>
        /// <param name="request">What to redact, and why.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <example>
        /// <code>
        /// await db.RedactAuditTrailAsync(customer, new AuditRedactionRequest
        /// {
        ///     Reason = "Erasure request #4711",
        ///     Properties = new[] { "Name", "Email", "Phone" },
        ///     MetadataKeys = new[] { "ip" }
        /// });
        /// </code>
        /// </example>
        public static Task<AuditRedactionResult> RedactAuditTrailAsync(
            this DbContext context, object entity, AuditRedactionRequest request, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(entity);
            ArgumentNullException.ThrowIfNull(request);

            var entry = context.Entry(entity);
            var tableName = entry.Metadata.GetTableName()
                ?? throw new InvalidOperationException($"{entry.Metadata.DisplayName()} is not mapped to a table.");
            return context.RedactAuditTrailAsync(tableName, AuditEntryReader.FormatRecordId(entry, original: false), request, cancellationToken);
        }

        /// <summary>
        /// Redacts values from the audit entries of one row.
        /// </summary>
        /// <param name="context">A context with the audit trail enabled.</param>
        /// <param name="tableName">The audited table.</param>
        /// <param name="recordId">The primary key of the row (composite keys as <c>part1|part2</c>).</param>
        /// <param name="request">What to redact, and why.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        public static Task<AuditRedactionResult> RedactAuditTrailAsync(
            this DbContext context, string tableName, string recordId, AuditRedactionRequest request, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentException.ThrowIfNullOrEmpty(tableName);
            ArgumentException.ThrowIfNullOrEmpty(recordId);
            ArgumentNullException.ThrowIfNull(request);

            return AuditRedactor.RedactAsync(context, context.AuditLogs().ForRecord(tableName, recordId), request, cancellationToken);
        }

        /// <summary>
        /// Removes a user from the audit trail: the user id is redacted on every entry attributed to
        /// <paramref name="userId"/>, in every table. The changes themselves stay readable.
        /// </summary>
        /// <param name="context">A context with the audit trail enabled.</param>
        /// <param name="userId">The user to remove.</param>
        /// <param name="reason">Why, for example "Former employee, erasure request #12".</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        public static Task<AuditRedactionResult> RedactAuditUserAsync(
            this DbContext context, string userId, string reason, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentException.ThrowIfNullOrEmpty(userId);

            return AuditRedactor.RedactAsync(context, context.AuditLogs().ByUser(userId), new AuditRedactionRequest
            {
                Reason = reason,
                Properties = Array.Empty<string>(),
                RedactUserId = true
            }, cancellationToken);
        }

        /// <summary>
        /// Redacts values from any selection of audit entries, for example
        /// <c>db.AuditLogs().ForTable("Customers").Between(null, cutoff)</c>.
        /// </summary>
        /// <param name="context">A context with the audit trail enabled.</param>
        /// <param name="entries">The entries to redact.</param>
        /// <param name="request">What to redact, and why.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        public static Task<AuditRedactionResult> RedactAuditEntriesAsync(
            this DbContext context, IQueryable<AuditLog> entries, AuditRedactionRequest request, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(entries);
            ArgumentNullException.ThrowIfNull(request);

            return AuditRedactor.RedactAsync(context, entries, request, cancellationToken);
        }
    }
}
