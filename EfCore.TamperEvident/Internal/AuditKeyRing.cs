using System.Text;
using EfCore.TamperEvident.Configuration;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// The HMAC secrets that are known to the application: the current one and the retired ones.
    /// </summary>
    internal sealed class AuditKeyRing
    {
        private static readonly byte[][] NoKeys = Array.Empty<byte[]>();

        private readonly Dictionary<string, byte[]> _byId = new(StringComparer.Ordinal);
        private readonly byte[][] _all;

        private AuditKeyRing(string? currentKeyId, byte[] currentKey, Dictionary<string, byte[]> retired)
        {
            CurrentKeyId = string.IsNullOrEmpty(currentKeyId) ? null : currentKeyId;
            CurrentKey = currentKey;

            var all = new List<byte[]> { currentKey };
            if (CurrentKeyId != null)
            {
                _byId[CurrentKeyId] = currentKey;
            }

            foreach (var (id, key) in retired)
            {
                _byId[id] = key;
                all.Add(key);
            }

            _all = all.ToArray();
        }

        public string? CurrentKeyId { get; }

        public byte[] CurrentKey { get; }

        public static AuditKeyRing Create(TamperEvidentOptions options)
        {
            var retired = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (var (id, secret) in options.AdditionalHmacKeys)
            {
                if (!string.Equals(id, options.HmacKeyId, StringComparison.Ordinal))
                {
                    retired[id] = Encoding.UTF8.GetBytes(secret);
                }
            }

            return new AuditKeyRing(options.HmacKeyId, Encoding.UTF8.GetBytes(options.HmacSecretKey), retired);
        }

        /// <summary>
        /// The keys an entry sealed with <paramref name="keyId"/> may have been authenticated with.
        /// An entry without a key id predates key rotation, so every key is a candidate.
        /// </summary>
        public IReadOnlyList<byte[]> Candidates(string? keyId)
        {
            if (string.IsNullOrEmpty(keyId))
            {
                return _all;
            }

            return _byId.TryGetValue(keyId, out var key) ? new[] { key } : NoKeys;
        }
    }
}
