namespace EfCore.TamperEvident
{
    /// <summary>
    /// Excludes an entity type from the audit trail, or a property from the audited values.
    /// Use it for data that must never be copied into the audit log (password hashes, tokens...).
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Property | AttributeTargets.Field, AllowMultiple = false, Inherited = true)]
    public sealed class AuditIgnoreAttribute : Attribute
    {
    }
}
