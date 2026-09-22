using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Models;

namespace EfCore.TamperEvident.Services
{
    public static class SecurityHelper
    {
        public static string GetLockQuery(DatabaseProvider provider) => provider switch
        {
            DatabaseProvider.SqlServer => "SELECT * FROM AuditChainStates WITH (UPDLOCK, ROWLOCK) WHERE TableName = {0}",
            DatabaseProvider.PostgreSql => "SELECT * FROM \"AuditChainStates\" WHERE \"TableName\" = {0} FOR UPDATE",
            DatabaseProvider.MySql => "SELECT * FROM AuditChainStates WHERE TableName = {0} FOR UPDATE",
            _ => throw new NotSupportedException("Unsupported database provider")
        };
        public static string? SerializeDeterministic(object? value)
        {
            if (value == null) return null;
            using var document = JsonDocument.Parse(JsonSerializer.Serialize(value));
            using var output = new System.IO.MemoryStream();
            using (var writer = new Utf8JsonWriter(output)) WriteCanonical(writer, document.RootElement);
            return Encoding.UTF8.GetString(output.ToArray());
        }
        private static void WriteCanonical(Utf8JsonWriter writer, JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                writer.WriteStartObject();
                foreach (var property in value.EnumerateObject().OrderBy(x => x.Name, StringComparer.Ordinal))
                { writer.WritePropertyName(property.Name); WriteCanonical(writer, property.Value); }
                writer.WriteEndObject();
            }
            else if (value.ValueKind == JsonValueKind.Array)
            {
                writer.WriteStartArray();
                foreach (var item in value.EnumerateArray()) WriteCanonical(writer, item);
                writer.WriteEndArray();
            }
            else value.WriteTo(writer);
        }
        public static string ComputeHash(string rawData, string encodedSecretKey)
        {
            var key = Convert.FromBase64String(encodedSecretKey);
            if (key.Length < 32) throw new InvalidOperationException("The HMAC key must decode to at least 32 bytes.");
            try
            {
                using var hmac = new HMACSHA256(key);
                return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(rawData))).ToLowerInvariant();
            }
            finally { Array.Clear(key, 0, key.Length); }
        }
        private static void Field(StringBuilder builder, string? value)
        {
            if (value == null) { builder.Append("-1#"); return; }
            builder.Append(Encoding.UTF8.GetByteCount(value).ToString(CultureInfo.InvariantCulture)).Append('#').Append(value);
        }
        public static string ComputeAuditHash(AuditLog log, string encodedSecretKey)
        {
            var payload = new StringBuilder();
            Field(payload, "audit-v2");
            Field(payload, log.Id.ToString("N"));
            Field(payload, log.PreviousHash);
            Field(payload, log.TableName);
            Field(payload, log.RecordId);
            Field(payload, log.ActionType);
            Field(payload, log.OldValues);
            Field(payload, log.NewValues);
            Field(payload, log.UserId);
            Field(payload, log.TimestampTicks.ToString(CultureInfo.InvariantCulture));
            return "v2:" + ComputeHash(payload.ToString(), encodedSecretKey);
        }
    }
}
