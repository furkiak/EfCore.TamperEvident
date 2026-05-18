using System.ComponentModel.DataAnnotations;

namespace EfCore.TamperEvident.Models
{
    public class AuditLog
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();
        public required string TableName { get; set; }
        public required string RecordId { get; set; }
        public required string ActionType { get; set; }  
        public string? OldValues { get; set; }  
        public string? NewValues { get; set; }  
        public required string UserId { get; set; } 
        public long TimestampTicks { get; set; } 
        public required string PreviousHash { get; set; }
        public required string CurrentHash { get; set; }
    }
}