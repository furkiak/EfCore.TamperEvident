using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using EfCore.TamperEvident.Models;

namespace EfCore.TamperEvident.Services
{
    public class AuditVerifier
    {
        private readonly DbContext _context;
        private readonly EfCore.TamperEvident.Configuration.TamperEvidentOptions _options;

        public AuditVerifier(DbContext context, EfCore.TamperEvident.Configuration.TamperEvidentOptions options)
        {
            _context = context;
            _options = options ?? new EfCore.TamperEvident.Configuration.TamperEvidentOptions();
        }

        public async Task<(bool IsValid, string Message)> VerifyTableIntegrityAsync(string tableName, List<string>? providedAnchorKeys = null)
        {
            var logsQuery = _context.Set<AuditLog>()
                .AsNoTracking()
                .Where(x => x.TableName == tableName)
                .OrderBy(x => x.TimestampTicks);

            if (!await logsQuery.AnyAsync())
                return (true, "No audit logs found for the specified table.");

            string expectedPreviousHash = "GENESIS";
            int matchedAnchors = 0;

            await foreach (var log in logsQuery.AsAsyncEnumerable())
            { 
                if (log.PreviousHash != expectedPreviousHash)
                    return (false, $"CHAIN BROKEN! Tampering detected at record ID: {log.Id}. The previous hash does not match.");
                 
                string rawData = $"{log.PreviousHash}{log.TableName}{log.RecordId}{log.ActionType}{log.OldValues}{log.NewValues}{log.TimestampTicks}";
                string recalculatedHash = SecurityHelper.ComputeHash(rawData, _options.HmacSecretKey);

                if (recalculatedHash != log.CurrentHash)
                    return (false, $"DATA MANIPULATION DETECTED! The payload of record ID: {log.Id} has been externally modified.");
                 
                if (providedAnchorKeys != null && providedAnchorKeys.Contains(log.CurrentHash))
                {
                    matchedAnchors++;
                    providedAnchorKeys.Remove(log.CurrentHash);
                }

                expectedPreviousHash = log.CurrentHash;
            } 
            if (providedAnchorKeys != null && providedAnchorKeys.Any())
            {
                return (false, "ANCHOR MISMATCH! The provided anchor keys were not found in the database. The database history has likely been regenerated (Hash Recalculation Attack).");
            }

            return (true, $"All verifications passed successfully! The hash chain is intact, and {matchedAnchors} anchors were successfully verified.");
        }
    }
}