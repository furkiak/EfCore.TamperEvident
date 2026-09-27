using System;
using System.Collections.Generic;
using System.Linq;
using EfCore.TamperEvident.Services;
using Microsoft.Extensions.Logging;

namespace EfCore.TamperEvident.Configuration
{
    [Flags]
    public enum AuditOperation
    {
        None = 0,
        Insert = 1,
        Update = 2,
        Delete = 4,
        All = Insert | Update | Delete
    }

    public enum DatabaseProvider
    {
        SqlServer,
        PostgreSql,
        MySql
    }

    public class TamperEvidentOptions
    {
        public string HmacSecretKey { get; set; } = "";
        public Func<Microsoft.EntityFrameworkCore.DbContext, string>? UserIdProvider { get; set; }
        public string SoftDeleteColumnName { get; set; } = "IsDeleted";
        
        public IAnchorPublisher? CustomAnchorPublisher { get; set; }
        public ILoggerFactory? LoggerFactory { get; set; }

        public DatabaseProvider DbProvider { get; set; } = DatabaseProvider.SqlServer;
        public AuditOperation TrackedOperations { get; set; } = AuditOperation.All;
        public List<string> ExcludedTables { get; set; } = new List<string>();
        public List<string> RedactedProperties { get; set; } = new List<string>
        {
            "Password", "PasswordHash", "ApiKey", "Secret", "Token",
            "AccessToken", "RefreshToken", "ConnectionString"
        };
        public int AnchorThreshold { get; set; } = 1000;
        public string? SmtpHost { get; set; }
        public int SmtpPort { get; set; } = 587;
        public string? SmtpUser { get; set; }
        public string? SmtpPassword { get; set; }
        public string? AnchorEmailTo { get; set; }
        public int SmtpTimeoutSeconds { get; set; } = 30;
        // Test sinks only. A remote host must always use TLS.
        public bool AllowUnencryptedLoopbackSmtp { get; set; }

        public void Validate()
        {
            byte[] key;
            try { key = Convert.FromBase64String(HmacSecretKey ?? ""); }
            catch (FormatException) { throw new InvalidOperationException("HmacSecretKey must be base64-encoded key material of at least 32 random bytes."); }
            try
            {
                if (key.Length < 32 || key.All(x => x == key[0]))
                    throw new InvalidOperationException("HmacSecretKey must be base64-encoded key material of at least 32 random bytes.");
            }
            finally { Array.Clear(key, 0, key.Length); }
            if (AnchorThreshold < 1) throw new InvalidOperationException("AnchorThreshold must be positive.");
            if (SmtpTimeoutSeconds < 1) throw new InvalidOperationException("SmtpTimeoutSeconds must be positive.");
            if (AllowUnencryptedLoopbackSmtp &&
                (!System.Net.IPAddress.TryParse(SmtpHost, out var address) || !System.Net.IPAddress.IsLoopback(address)))
                throw new InvalidOperationException("Unencrypted test SMTP requires a literal loopback IP address.");
        }
    }
}
