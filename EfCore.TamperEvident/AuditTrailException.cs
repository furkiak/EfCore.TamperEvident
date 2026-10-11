namespace EfCore.TamperEvident
{
    /// <summary>
    /// Thrown when the audit trail of a change could not be written. The audited change is not persisted either:
    /// a transaction that the interceptor started is rolled back. The exception is deliberately not transient, so
    /// retrying execution strategies do not re-run the save against a context whose changes were already accepted.
    /// Discard the <c>DbContext</c> and repeat the operation with a new one.
    /// </summary>
    public class AuditTrailException : Exception
    {
        /// <summary>Creates the exception.</summary>
        public AuditTrailException()
        {
        }

        /// <summary>Creates the exception.</summary>
        /// <param name="message">The message.</param>
        public AuditTrailException(string message)
            : base(message)
        {
        }

        /// <summary>Creates the exception.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The error that prevented the audit entry from being written.</param>
        public AuditTrailException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
