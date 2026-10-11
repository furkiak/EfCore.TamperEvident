using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using EfCore.TamperEvident.Models;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>An audit entry as it is exported (JSON Lines and evidence bundles), with everything its hash covers.</summary>
    internal sealed class EvidenceRecord
    {
        public static readonly JsonSerializerOptions Json = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never
        };

        public Guid Id { get; set; }

        public string TableName { get; set; } = string.Empty;

        public string RecordId { get; set; } = string.Empty;

        public string ActionType { get; set; } = string.Empty;

        public string UserId { get; set; } = string.Empty;

        public DateTime TimestampUtc { get; set; }

        /// <summary>The exact timestamp the hash covers.</summary>
        public long TimestampTicks { get; set; }

        public long SequenceNumber { get; set; }

        public int HashVersion { get; set; }

        public string? KeyId { get; set; }

        public string PreviousHash { get; set; } = string.Empty;

        public string CurrentHash { get; set; } = string.Empty;

        public string? OldValues { get; set; }

        public string? NewValues { get; set; }

        public string? Metadata { get; set; }

        public static EvidenceRecord From(AuditLog log) => new()
        {
            Id = log.Id,
            TableName = log.TableName,
            RecordId = log.RecordId,
            ActionType = log.ActionType,
            UserId = log.UserId,
            TimestampUtc = log.TimestampUtc,
            TimestampTicks = log.TimestampTicks,
            SequenceNumber = log.SequenceNumber,
            HashVersion = log.HashVersion,
            KeyId = log.KeyId,
            PreviousHash = log.PreviousHash,
            CurrentHash = log.CurrentHash,
            OldValues = log.OldValues,
            NewValues = log.NewValues,
            Metadata = log.Metadata
        };

        public AuditLog ToLog() => new()
        {
            Id = Id,
            TableName = TableName,
            RecordId = RecordId,
            ActionType = ActionType,
            UserId = UserId,
            TimestampTicks = TimestampTicks != 0 ? TimestampTicks : DateTime.SpecifyKind(TimestampUtc, DateTimeKind.Utc).Ticks,
            SequenceNumber = SequenceNumber,
            HashVersion = HashVersion,
            KeyId = KeyId,
            PreviousHash = PreviousHash,
            CurrentHash = CurrentHash,
            OldValues = OldValues,
            NewValues = NewValues,
            Metadata = Metadata
        };
    }

    /// <summary>A signed chain head as it is exported in evidence bundles.</summary>
    internal sealed class EvidenceHead
    {
        public string TableName { get; set; } = string.Empty;

        public string LastHash { get; set; } = string.Empty;

        public long LastSequence { get; set; }

        public string? KeyId { get; set; }

        public string? Mac { get; set; }

        public static EvidenceHead From(AuditChainState state) => new()
        {
            TableName = state.TableName,
            LastHash = state.LastHash,
            LastSequence = state.LastSequence,
            KeyId = state.KeyId,
            Mac = state.Mac
        };

        public AuditChainState ToState() => new()
        {
            TableName = TableName,
            LastHash = LastHash,
            LastSequence = LastSequence,
            KeyId = KeyId,
            Mac = Mac
        };
    }
}
