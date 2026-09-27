using System.Threading.Tasks;

namespace EfCore.TamperEvident.Services
{
    public interface IAnchorPublisher
    {
        Task SendAnchorAsync(string tableName, string currentHash, int recordCount);

        // Existing publishers stay compatible; implement this overload to deduplicate by Id.
        Task SendAnchorAsync(AnchorDelivery anchor, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SendAnchorAsync(anchor.TableName, anchor.AnchorHash, anchor.RecordCount);
        }
    }
}
