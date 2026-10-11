using EfCore.TamperEvident.Services;

namespace EfCore.TamperEvident.AspNetCore
{
    /// <summary>
    /// The outcome of the most recent verification of the whole audit trail.
    /// </summary>
    /// <param name="Report">The verification report.</param>
    /// <param name="Source">Who ran it: <c>background</c> (the hosted service) or <c>manual</c> (the dashboard).</param>
    public sealed record AuditVerificationSnapshot(AuditVerificationReport Report, string Source);

    /// <summary>
    /// Remembers the latest verification so that the health check and the dashboard can report it without
    /// verifying again. Registered as a singleton by <c>AddTamperEvidentVerification</c>.
    /// </summary>
    public sealed class AuditVerificationState
    {
        private volatile AuditVerificationSnapshot? _latest;

        /// <summary>The latest verification, or <c>null</c> when none ran yet.</summary>
        public AuditVerificationSnapshot? Latest => _latest;

        /// <summary>Stores a new result.</summary>
        /// <param name="report">The report.</param>
        /// <param name="source">Who ran the verification.</param>
        public void Update(AuditVerificationReport report, string source)
        {
            ArgumentNullException.ThrowIfNull(report);
            _latest = new AuditVerificationSnapshot(report, source);
        }
    }
}
