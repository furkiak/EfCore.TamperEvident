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
            _options = options ?? throw new System.ArgumentNullException(nameof(options));
            _options.Validate();
        }

        public async Task<(bool IsValid, string Message)> VerifyTableIntegrityAsync(
            string tableName, IReadOnlyList<string>? providedAnchorKeys = null,
            CancellationToken cancellationToken = default)
        {
            var logsQuery = _context.Set<AuditLog>()
                .AsNoTracking()
                .Where(x => x.TableName == tableName)
                .OrderBy(x => x.TimestampTicks);

            if (!await logsQuery.AnyAsync(cancellationToken))
            {
                if (providedAnchorKeys?.Count > 0)
                    return (false, "ANCHOR MISMATCH! External anchors exist but all audit rows are missing.");
                if (await _context.Set<AuditChainState>().AsNoTracking().AnyAsync(x => x.TableName == tableName, cancellationToken))
                    return (false, "CHAIN BROKEN! Chain state exists but all audit rows are missing.");
                return (false, "INCONCLUSIVE: no audit history or trusted external anchor was supplied for this table.");
            }

            string expectedPreviousHash = "GENESIS";
            long lastTimestampTicks = 0;
            int matchedAnchors = 0;
            var unmatchedAnchors = providedAnchorKeys == null ? null :
                new Queue<string>(providedAnchorKeys);

            await foreach (var log in logsQuery.AsAsyncEnumerable().WithCancellation(cancellationToken))
            { 
                if (log.PreviousHash != expectedPreviousHash)
                    return (false, $"CHAIN BROKEN! Tampering detected at record ID: {log.Id}. The previous hash does not match.");
                 
                if (!log.CurrentHash.StartsWith("v2:", System.StringComparison.Ordinal))
                    return (false, "Legacy audit format cannot be trusted by the v2 verifier; preserve it for explicit migration and compare its last external anchor separately.");
                string recalculatedHash = SecurityHelper.ComputeAuditHash(log, _options.HmacSecretKey);

                if (recalculatedHash != log.CurrentHash)
                    return (false, $"DATA MANIPULATION DETECTED! The payload of record ID: {log.Id} has been externally modified.");
                 
                if (unmatchedAnchors?.Count > 0 && unmatchedAnchors.Peek() == log.CurrentHash)
                {
                    unmatchedAnchors.Dequeue();
                    matchedAnchors++;
                }

                expectedPreviousHash = log.CurrentHash;
                lastTimestampTicks = log.TimestampTicks;
            } 
            if (unmatchedAnchors?.Count > 0)
            {
                return (false, "ANCHOR MISMATCH! At least one external anchor is missing, extra or out of chain order.");
            }

            var state = await _context.Set<AuditChainState>().AsNoTracking().FirstOrDefaultAsync(x => x.TableName == tableName, cancellationToken);
            if (state == null || state.LastHash != expectedPreviousHash || state.LastTimestampTicks != lastTimestampTicks)
                return (false, "CHAIN BROKEN! The final audit hash or timestamp does not match chain state.");
            return (true, $"All verifications passed successfully! The hash chain is intact, and {matchedAnchors} anchors were successfully verified.");
        }
    }
}
