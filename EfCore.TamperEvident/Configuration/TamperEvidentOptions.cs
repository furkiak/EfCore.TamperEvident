using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace EfCore.TamperEvident.Configuration
{
    /// <summary>
    /// Configures the tamper-evident audit trail.
    /// </summary>
    public class TamperEvidentOptions
    {
        /// <summary>The shortest accepted <see cref="HmacSecretKey"/>. Use 32 or more random characters.</summary>
        public const int MinimumSecretKeyLength = 16;

        // The default key that 1.x shipped with. It is public knowledge and therefore refused.
        internal const string LegacyDefaultKey = "Th1s!sA_D3f4u1t_0bfu5c4t10n_K3y_For_HMAC_TAMPER_EVIDENT";

        /// <summary>
        /// The secret that every hash is keyed with. It must stay outside of the audited database
        /// (user secrets, environment variable, key vault...). Whoever knows it can forge a chain.
        /// There is intentionally no default.
        /// </summary>
        public string HmacSecretKey { get; set; } = string.Empty;

        /// <summary>
        /// Optional identifier of <see cref="HmacSecretKey"/>. It is stored with every entry so that
        /// the secret can be rotated: move the retired secret to <see cref="AdditionalHmacKeys"/>
        /// and give the new one a new id.
        /// </summary>
        public string? HmacKeyId { get; set; }

        /// <summary>
        /// Retired secrets (key id to secret) that are still needed to verify older entries.
        /// Entries without a key id are verified against every configured secret.
        /// </summary>
        public IDictionary<string, string> AdditionalHmacKeys { get; } =
            new Dictionary<string, string>(StringComparer.Ordinal);

        /// <summary>
        /// Name of the soft delete property. A <c>bool</c> flipping to <c>true</c>, or a nullable date
        /// that gets a value, is recorded as <see cref="Models.AuditActions.SoftDelete"/>.
        /// </summary>
        public string SoftDeleteColumnName { get; set; } = "IsDeleted";

        /// <summary>The publisher that receives anchors. When <c>null</c> the SMTP settings are used.</summary>
        public IAnchorPublisher? CustomAnchorPublisher { get; set; }

        /// <summary>Optional logger factory. Falls back to the one registered in the <c>DbContext</c> services.</summary>
        public ILoggerFactory? LoggerFactory { get; set; }

        /// <summary>
        /// The database provider. <see cref="DatabaseProvider.Auto"/> (the default) detects it from the
        /// <c>DbContext</c>; set a value only to override the detection.
        /// </summary>
        public DatabaseProvider DbProvider { get; set; } = DatabaseProvider.Auto;

        /// <summary>The kinds of changes that are audited.</summary>
        public AuditOperation TrackedOperations { get; set; } = AuditOperation.All;

        /// <summary>Tables that are not audited (case-insensitive).</summary>
        public List<string> ExcludedTables { get; set; } = new List<string>();

        /// <summary>Property names that are never copied into the audit trail, on any entity (case-insensitive).</summary>
        public List<string> ExcludedProperties { get; set; } = new List<string>();

        /// <summary>
        /// Property names whose values are replaced with a keyed fingerprint, on any entity (case-insensitive).
        /// Use <see cref="AuditMaskAttribute"/> to mask a single property.
        /// </summary>
        public List<string> MaskedProperties { get; set; } = new List<string>();

        /// <summary>
        /// A new anchor is published every time this many entries were written to a table.
        /// Zero or a negative value disables anchoring. Defaults to 1000.
        /// </summary>
        public int AnchorThreshold { get; set; } = 1000;

        /// <summary>How often delivering an anchor is attempted before giving up. Defaults to 3.</summary>
        public int AnchorMaxAttempts { get; set; } = 3;

        /// <summary>Delay before the first retry; it doubles for every further attempt. Defaults to two seconds.</summary>
        public TimeSpan AnchorRetryDelay { get; set; } = TimeSpan.FromSeconds(2);

        /// <summary>
        /// When <c>true</c>, <c>SaveChanges</c> waits until the anchor was handed to the publisher.
        /// By default anchors are delivered in the background.
        /// </summary>
        public bool AwaitAnchorDelivery { get; set; }

        /// <summary>SMTP host used by the built-in e-mail anchor publisher.</summary>
        public string? SmtpHost { get; set; }

        /// <summary>SMTP port. Defaults to 587.</summary>
        public int SmtpPort { get; set; } = 587;

        /// <summary>Whether the SMTP connection is encrypted. Defaults to <c>true</c>.</summary>
        public bool SmtpEnableSsl { get; set; } = true;

        /// <summary>SMTP user, also used as the sender address.</summary>
        public string? SmtpUser { get; set; }

        /// <summary>SMTP password.</summary>
        public string? SmtpPassword { get; set; }

        /// <summary>Recipient(s) of the anchor e-mails. Separate several addresses with a comma.</summary>
        public string? AnchorEmailTo { get; set; }

        /// <summary>
        /// Resolves the user a change is attributed to. Called once per <c>SaveChanges</c>.
        /// An active <see cref="AuditScope"/> takes precedence over it.
        /// </summary>
        public Func<DbContext, string?>? UserIdProvider { get; set; }

        /// <summary>The user recorded when no user can be resolved. Defaults to <c>System</c>.</summary>
        public string DefaultUserId { get; set; } = "System";

        /// <summary>The clock used for timestamps. Replace it in tests.</summary>
        public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

        /// <summary>
        /// Throws <see cref="InvalidOperationException"/> when the configuration cannot produce a trustworthy trail.
        /// It is called automatically when the audit is registered.
        /// </summary>
        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(HmacSecretKey))
            {
                throw new InvalidOperationException(
                    $"{nameof(TamperEvidentOptions)}.{nameof(HmacSecretKey)} is not set. Provide a long random secret " +
                    "that is stored outside of the audited database (for example: openssl rand -base64 48).");
            }

            if (string.Equals(HmacSecretKey, LegacyDefaultKey, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"{nameof(TamperEvidentOptions)}.{nameof(HmacSecretKey)} is set to the default key that older versions " +
                    "shipped with. That value is public, so anybody could forge a valid chain. Configure your own secret.");
            }

            if (HmacSecretKey.Length < MinimumSecretKeyLength)
            {
                throw new InvalidOperationException(
                    $"{nameof(TamperEvidentOptions)}.{nameof(HmacSecretKey)} must be at least {MinimumSecretKeyLength} characters " +
                    "long (32 or more recommended).");
            }

            if (HmacKeyId is { Length: > 64 })
            {
                throw new InvalidOperationException($"{nameof(HmacKeyId)} must not be longer than 64 characters.");
            }

            foreach (var (id, secret) in AdditionalHmacKeys)
            {
                if (string.IsNullOrWhiteSpace(id) || id.Length > 64)
                {
                    throw new InvalidOperationException($"Every key id in {nameof(AdditionalHmacKeys)} must be 1-64 characters long.");
                }

                if (string.IsNullOrEmpty(secret))
                {
                    throw new InvalidOperationException($"The secret of key '{id}' in {nameof(AdditionalHmacKeys)} is empty.");
                }
            }

            if (AnchorMaxAttempts < 1)
            {
                throw new InvalidOperationException($"{nameof(AnchorMaxAttempts)} must be at least 1.");
            }
        }
    }
}
