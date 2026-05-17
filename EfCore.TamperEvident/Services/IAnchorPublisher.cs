using System.Threading.Tasks;

namespace EfCore.TamperEvident.Services
{
    public interface IAnchorPublisher
    {
        Task SendAnchorAsync(string tableName, string currentHash, int recordCount);
    }
}
