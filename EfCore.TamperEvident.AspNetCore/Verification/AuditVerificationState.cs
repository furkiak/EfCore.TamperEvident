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
    /// verifying again, and the checkpoints that let the next scheduled verification read only new entries.
    /// Registered as a singleton by <c>AddTamperEvidentVerification</c>.
    /// </summary>
    public sealed class AuditVerificationState
    {
        private readonly object _gate = new();
        private volatile AuditVerificationSnapshot? _latest;
        private IReadOnlyDictionary<string, AuditCheckpoint>? _checkpoints;
        private DateTimeOffset? _lastFull;

        /// <summary>The latest verification, or <c>null</c> when none ran yet.</summary>
        public AuditVerificationSnapshot? Latest => _latest;

        /// <summary>When the whole trail was last verified from the start, or <c>null</c> when it never was.</summary>
        public DateTimeOffset? LastFullVerificationUtc
        {
            get
            {
                lock (_gate)
                {
                    return _lastFull;
                }
            }
        }

        /// <summary>
        /// The checkpoints of the last successful verification. They live in memory only, out of reach of anybody who
        /// can write to the database; after a restart the next verification is a full one.
        /// </summary>
        public IReadOnlyDictionary<string, AuditCheckpoint>? Checkpoints
        {
            get
            {
                lock (_gate)
                {
                    return _checkpoints;
                }
            }
        }

        /// <summary>Stores a new result.</summary>
        /// <param name="report">The report.</param>
        /// <param name="source">Who ran the verification.</param>
        public void Update(AuditVerificationReport report, string source)
        {
            ArgumentNullException.ThrowIfNull(report);
            _latest = new AuditVerificationSnapshot(report, source);
        }

        /// <summary>Records a verification of every table from the start of its chain.</summary>
        /// <param name="report">The report.</param>
        public void RecordFullVerification(AuditVerificationReport report)
        {
            ArgumentNullException.ThrowIfNull(report);
            lock (_gate)
            {
                _checkpoints = report.IsValid ? report.Checkpoints : null;
                _lastFull = report.IsValid ? report.CompletedUtc : _lastFull;
            }
        }

        /// <summary>Records a verification that started at the stored checkpoints.</summary>
        /// <param name="report">The report.</param>
        public void RecordIncrementalVerification(AuditVerificationReport report)
        {
            ArgumentNullException.ThrowIfNull(report);
            lock (_gate)
            {
                // A failure forgets the checkpoints: the next run looks at everything again.
                _checkpoints = report.IsValid ? report.Checkpoints : null;
            }
        }
    }
}
