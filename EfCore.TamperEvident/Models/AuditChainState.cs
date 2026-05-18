using System.ComponentModel.DataAnnotations;

namespace EfCore.TamperEvident.Models
{
    public class AuditChainState
    {
        [Key]
        public required string TableName { get; set; }
        public required string LastHash { get; set; }
        public int UnanchoredCount { get; set; }  
        public DateTime LastModified { get; set; } = DateTime.UtcNow;
    }
}