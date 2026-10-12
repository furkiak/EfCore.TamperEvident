using EfCore.TamperEvident.Services;

namespace EfCore.TamperEvident.AspNetCore
{
    /// <summary>
    /// Configures the scheduled verification of the audit trail.
    /// </summary>
    public sealed class TamperEvidentVerificationOptions
    {
        /// <summary>Time between two verifications. Defaults to one hour.</summary>
        public TimeSpan Interval { get; set; } = TimeSpan.FromHours(1);

        /// <summary>Time to wait after the application started before the first verification. Defaults to one minute.</summary>
        public TimeSpan InitialDelay { get; set; } = TimeSpan.FromMinutes(1);

        /// <summary>
        /// Between full verifications, verify only the entries appended since the previous successful run (see
        /// <see cref="AuditVerifier.VerifyFromCheckpointAsync"/>). The cost of a run then depends on the number of new
        /// entries instead of the size of the trail. Defaults to <c>true</c>.
        /// </summary>
        public bool Incremental { get; set; } = true;

        /// <summary>
        /// How often the whole trail is verified from the start when <see cref="Incremental"/> is on: only a full
        /// verification re-reads old entries. The first run after a start is always full. Defaults to 24 hours.
        /// </summary>
        public TimeSpan FullVerificationInterval { get; set; } = TimeSpan.FromHours(24);

        /// <summary>
        /// Supplies the externally stored anchors (table to anchor hashes) every verification is checked against, for
        /// example <see cref="AnchorSources.FromFile(string)"/>. Without it only the chain itself is verified.
        /// </summary>
        public Func<IServiceProvider, CancellationToken, Task<IReadOnlyDictionary<string, IEnumerable<string>>?>>? AnchorProvider { get; set; }

        /// <summary>
        /// Called when a verification finds a broken chain: send a page, open an incident, shut something down...
        /// Exceptions thrown by the callback are logged and do not stop the service.
        /// </summary>
        public Func<AuditVerificationReport, IServiceProvider, CancellationToken, Task>? OnTamperDetected { get; set; }
    }
}
