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
