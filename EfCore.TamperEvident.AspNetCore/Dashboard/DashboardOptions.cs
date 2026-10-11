using EfCore.TamperEvident.Configuration;

namespace EfCore.TamperEvident.AspNetCore
{
    /// <summary>
    /// Configures the audit dashboard.
    /// </summary>
    public sealed class DashboardOptions
    {
        /// <summary>The title shown in the dashboard. Defaults to <c>Tamper Evident</c>.</summary>
        public string Title { get; set; } = "Tamper Evident";

        /// <summary>
        /// The dashboard shows who changed what, so outside of the Development environment it refuses to serve unless
        /// it is protected with <c>RequireAuthorization()</c>. Set this to <c>true</c> to accept the risk of serving it
        /// without authorization (for example behind an authenticating reverse proxy).
        /// </summary>
        public bool AllowAnonymous { get; set; }

        /// <summary>Whether entries can be exported (JSON Lines, CSV, evidence bundle). Defaults to <c>true</c>.</summary>
        public bool AllowExport { get; set; } = true;

        /// <summary>
        /// The options that hold the secret key, needed to verify the chains. When <c>null</c> the
        /// <see cref="TamperEvidentOptions"/> registered with <c>AddTamperEvident</c> is used; without either,
        /// the dashboard can browse the trail but not verify it.
        /// </summary>
        public TamperEvidentOptions? AuditOptions { get; set; }

        /// <summary>
        /// Supplies externally stored anchors that every verification started from the dashboard is checked against,
        /// for example <see cref="AnchorSources.FromFile(string)"/>.
        /// </summary>
        public Func<IServiceProvider, CancellationToken, Task<IReadOnlyDictionary<string, IEnumerable<string>>?>>? AnchorProvider { get; set; }

        /// <summary>The largest page the entries API returns. Defaults to 200.</summary>
        public int MaxPageSize { get; set; } = 200;
    }
}
