using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Extensions
{
    /// <summary>
    /// Model configuration for the audit tables.
    /// </summary>
    public static class ModelBuilderExtensions
    {
        /// <summary>
        /// Adds the audit tables to the model, so no <c>DbSet</c> properties are needed, and optionally
        /// places them in a schema. Call it from <c>OnModelCreating</c>, then add a migration.
        /// </summary>
        /// <param name="modelBuilder">The model builder.</param>
        /// <param name="schema">An optional schema for both tables.</param>
        /// <param name="auditLogTable">The name of the audit log table.</param>
        /// <param name="chainStateTable">The name of the chain head table.</param>
        /// <returns>The same builder, for chaining.</returns>
        public static ModelBuilder ApplyTamperEvidentAudit(
            this ModelBuilder modelBuilder,
            string? schema = null,
            string auditLogTable = "AuditLogs",
            string chainStateTable = "AuditChainStates")
        {
            ArgumentNullException.ThrowIfNull(modelBuilder);

            modelBuilder.Entity<AuditLog>().ToTable(auditLogTable, schema);
            modelBuilder.Entity<AuditChainState>().ToTable(chainStateTable, schema);
            return modelBuilder;
        }
    }
}
