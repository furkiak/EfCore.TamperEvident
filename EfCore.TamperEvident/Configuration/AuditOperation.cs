namespace EfCore.TamperEvident.Configuration
{
    /// <summary>
    /// The kinds of changes that are written to the audit trail.
    /// </summary>
    [Flags]
    public enum AuditOperation
    {
        /// <summary>Nothing is audited.</summary>
        None = 0,

        /// <summary>Inserts are audited.</summary>
        Insert = 1,

        /// <summary>Updates (including soft deletes) are audited.</summary>
        Update = 2,

        /// <summary>Physical deletes are audited.</summary>
        Delete = 4,

        /// <summary>Everything is audited.</summary>
        All = Insert | Update | Delete
    }
}
