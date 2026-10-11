namespace EfCore.TamperEvident
{
    /// <summary>
    /// Replaces the value of a property with a keyed fingerprint (<c>[MASKED:1a2b3c4d]</c>) in the audit trail.
    /// The clear text is never stored, yet it stays provable <em>that</em> the value changed.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field, AllowMultiple = false, Inherited = true)]
    public sealed class AuditMaskAttribute : Attribute
    {
    }
}
