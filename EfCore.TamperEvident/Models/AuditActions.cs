namespace EfCore.TamperEvident.Models
{
    /// <summary>
    /// The values stored in <see cref="AuditLog.ActionType"/>.
    /// </summary>
    public static class AuditActions
    {
        /// <summary>A new row was inserted.</summary>
        public const string Added = "Added";

        /// <summary>An existing row was updated.</summary>
        public const string Modified = "Modified";

        /// <summary>A row was physically deleted.</summary>
        public const string Deleted = "Deleted";

        /// <summary>A row was logically deleted (for example <c>IsDeleted</c> changed from <c>false</c> to <c>true</c>).</summary>
        public const string SoftDelete = "SoftDelete";

        /// <summary>A logically deleted row was restored (for example <c>IsDeleted</c> changed from <c>true</c> to <c>false</c>).</summary>
        public const string Restored = "Restored";

        /// <summary>
        /// Values of earlier entries were redacted. The entry lists which values of which entries, and its metadata
        /// carries the reason. Verification only accepts a redacted value that such an entry authorizes.
        /// </summary>
        public const string Redacted = "Redacted";
    }
}
