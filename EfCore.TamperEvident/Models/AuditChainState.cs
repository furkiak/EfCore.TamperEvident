using System.ComponentModel.DataAnnotations;

namespace EfCore.TamperEvident.Models
{
    public class AuditChainState
    {
        [Key]
        public string TableName { get; set; }
        public string LastHash { get; set; }
        public int UnanchoredCount { get; set; }  
        public DateTime LastModified { get; set; } = DateTime.UtcNow;
    }
}