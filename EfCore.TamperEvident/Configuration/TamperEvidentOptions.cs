using System;
using System.Collections.Generic;
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
        public string HmacSecretKey { get; set; } = "Th1s!sA_D3f4u1t_0bfu5c4t10n_K3y_For_HMAC_TAMPER_EVIDENT";
        public string SoftDeleteColumnName { get; set; } = "IsDeleted";
        
        public IAnchorPublisher? CustomAnchorPublisher { get; set; }
        public ILoggerFactory? LoggerFactory { get; set; }

        public DatabaseProvider DbProvider { get; set; } = DatabaseProvider.SqlServer;
        public AuditOperation TrackedOperations { get; set; } = AuditOperation.All;
        public List<string> ExcludedTables { get; set; } = new List<string>();
        public int AnchorThreshold { get; set; } = 1000;
        public string? SmtpHost { get; set; }
        public int SmtpPort { get; set; } = 587;
        public string? SmtpUser { get; set; }
        public string? SmtpPassword { get; set; }
        public string? AnchorEmailTo { get; set; }
    }
}