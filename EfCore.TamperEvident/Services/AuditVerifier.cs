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

        public AuditVerifier(DbContext context)
        {
            _context = context;
        }

        public async Task<(bool IsValid, string Message)> VerifyTableIntegrityAsync(string tableName, List<string> providedAnchorKeys = null)
        {
            var logs = await _context.Set<AuditLog>()
                .AsNoTracking()
                .Where(x => x.TableName == tableName)
                .OrderBy(x => x.TimestampTicks)
                .ToListAsync();

            if (!logs.Any())
                return (true, "No audit logs found for the specified table.");

            string expectedPreviousHash = "GENESIS";
            int matchedAnchors = 0;

            foreach (var log in logs)
            { 
                if (log.PreviousHash != expectedPreviousHash)
                    return (false, $"CHAIN BROKEN! Tampering detected at record ID: {log.Id}. The previous hash does not match.");
                 
                string rawData = $"{log.PreviousHash}{log.TableName}{log.RecordId}{log.ActionType}{log.OldValues}{log.NewValues}{log.TimestampTicks}";
                string recalculatedHash = SecurityHelper.ComputeHash(rawData);

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