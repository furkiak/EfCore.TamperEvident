using System.ComponentModel.DataAnnotations;

namespace EfCore.TamperEvident.Models
{
    public class AuditLog
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();
        public string TableName { get; set; }
        public string RecordId { get; set; }
        public string ActionType { get; set; }  
        public string? OldValues { get; set; }  
        public string? NewValues { get; set; }  
        public string UserId { get; set; } 
        public long TimestampTicks { get; set; } 
        public string PreviousHash { get; set; }
        public string CurrentHash { get; set; }
    }
}