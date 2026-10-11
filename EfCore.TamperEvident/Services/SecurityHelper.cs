using System.Security.Cryptography;
using System.Text;
using EfCore.TamperEvident.Internal;

namespace EfCore.TamperEvident.Services
{
    /// <summary>
    /// Low level helpers that are useful when verifying or exporting audit data yourself.
    /// </summary>
    public static class SecurityHelper
    {
        /// <summary>
        /// Serializes an object to JSON whose bytes depend only on the data: property names are sorted with an
        /// ordinal comparison (nested objects included), so the result is identical on every machine and culture.
        /// </summary>
        /// <param name="obj">The value to serialize.</param>
        /// <returns>The JSON, or <c>null</c> when <paramref name="obj"/> is <c>null</c>.</returns>
        public static string? SerializeDeterministic(object? obj) => AuditSerializer.SerializeObject(obj);

        /// <summary>Computes HMAC-SHA256 of <paramref name="rawData"/> and returns it as lowercase hex.</summary>
        /// <param name="rawData">The data to authenticate.</param>
        /// <param name="secretKey">The secret.</param>
        public static string ComputeHash(string rawData, string? secretKey)
        {
            var key = Encoding.UTF8.GetBytes(secretKey ?? string.Empty);
            return Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(rawData))).ToLowerInvariant();
        }
    }
}
