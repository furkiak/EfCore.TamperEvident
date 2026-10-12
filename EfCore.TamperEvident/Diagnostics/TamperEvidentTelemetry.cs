using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Reflection;

namespace EfCore.TamperEvident.Diagnostics
{
    /// <summary>
    /// Traces and metrics of the audit trail, for OpenTelemetry or any other <see cref="ActivityListener"/> and
    /// <see cref="MeterListener"/>. Nothing is recorded unless somebody listens.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddOpenTelemetry()
    ///     .WithTracing(t => t.AddSource(TamperEvidentTelemetry.SourceName))
    ///     .WithMetrics(m => m.AddMeter(TamperEvidentTelemetry.SourceName));
    /// </code>
    /// </example>
    public static class TamperEvidentTelemetry
    {
        /// <summary>The name of the <see cref="ActivitySource"/> and of the <see cref="Meter"/>.</summary>
        public const string SourceName = "EfCore.TamperEvident";

        private static readonly string Version =
            typeof(TamperEvidentTelemetry).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
            ?? "2.0.0";

        internal static readonly ActivitySource Source = new(SourceName, Version);

        internal static readonly Meter Meter = new(SourceName, Version);

        internal static readonly Counter<long> EntriesSealed = Meter.CreateCounter<long>(
            "tamper_evident.entries.sealed", "{entry}", "Audit entries sealed into a hash chain.");

        internal static readonly Histogram<double> SealDuration = Meter.CreateHistogram<double>(
            "tamper_evident.seal.duration", "s", "Time spent sealing and writing the audit entries of one SaveChanges call.");

        internal static readonly Counter<long> Verifications = Meter.CreateCounter<long>(
            "tamper_evident.verifications", "{verification}", "Verified chains, by result.");

        internal static readonly Counter<long> EntriesVerified = Meter.CreateCounter<long>(
            "tamper_evident.entries.verified", "{entry}", "Audit entries whose hash was recomputed and checked.");

        internal static readonly Histogram<double> VerificationDuration = Meter.CreateHistogram<double>(
            "tamper_evident.verification.duration", "s", "Time spent verifying the chain of one table.");

        internal static readonly Counter<long> AnchorsPublished = Meter.CreateCounter<long>(
            "tamper_evident.anchors.published", "{anchor}", "Anchors handed to a publisher, by result.");

        internal static readonly Counter<long> ValuesRedacted = Meter.CreateCounter<long>(
            "tamper_evident.values.redacted", "{value}", "Values redacted from the audit trail.");

        /// <summary>Activity names, for filtering.</summary>
        public static class Activities
        {
            /// <summary>Sealing and writing the audit entries of one <c>SaveChanges</c> call.</summary>
            public const string Seal = "tamper_evident.seal";

            /// <summary>Verifying the chain of one table.</summary>
            public const string Verify = "tamper_evident.verify";

            /// <summary>Redacting values from the audit trail.</summary>
            public const string Redact = "tamper_evident.redact";

            /// <summary>Handing an anchor to a publisher.</summary>
            public const string PublishAnchor = "tamper_evident.anchor.publish";
        }

        /// <summary>Tag names used on activities and metrics.</summary>
        public static class Tags
        {
            /// <summary>The audited table.</summary>
            public const string Table = "tamper_evident.table";

            /// <summary>The number of entries.</summary>
            public const string Entries = "tamper_evident.entries";

            /// <summary>The outcome (<c>valid</c>, a failure kind, <c>success</c> or <c>failure</c>).</summary>
            public const string Result = "tamper_evident.result";

            /// <summary>Whether a verification started at a checkpoint.</summary>
            public const string Incremental = "tamper_evident.incremental";
        }
    }
}
