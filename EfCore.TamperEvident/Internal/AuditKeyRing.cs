using System.Security.Cryptography;
using System.Text;
using EfCore.TamperEvident.Configuration;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>One HMAC secret, together with the key derived from it for field digests.</summary>
    internal sealed class AuditKey
    {
        public AuditKey(string? id, byte[] secret)
        {
            Id = id;
            Secret = secret;

            // Field digests use their own key, so that a field digest can never be confused with a record hash.
            FieldKey = HMACSHA256.HashData(secret, "EfCore.TamperEvident/field-digest/v3"u8);
        }

        public string? Id { get; }

        /// <summary>Keys record hashes, chain head MACs and mask tokens.</summary>
        public byte[] Secret { get; }

        /// <summary>Keys the digests of the individual fields of a <see cref="Models.AuditHashVersion.Redactable"/> entry.</summary>
        public byte[] FieldKey { get; }
    }

    /// <summary>
    /// The HMAC secrets that are known to the application: the current one and the retired ones.
    /// </summary>
    internal sealed class AuditKeyRing
    {
        private static readonly AuditKey[] NoKeys = Array.Empty<AuditKey>();

        private readonly Dictionary<string, AuditKey> _byId = new(StringComparer.Ordinal);
        private readonly AuditKey[] _all;

        private AuditKeyRing(AuditKey current, IEnumerable<AuditKey> retired)
        {
            Current = current;

            var all = new List<AuditKey> { current };
            if (current.Id != null)
            {
                _byId[current.Id] = current;
            }

            foreach (var key in retired)
            {
                _byId[key.Id!] = key;
                all.Add(key);
            }

            _all = all.ToArray();
        }

        public AuditKey Current { get; }

        public string? CurrentKeyId => Current.Id;

        public byte[] CurrentKey => Current.Secret;

        public static AuditKeyRing Create(TamperEvidentOptions options)
        {
            var retired = new List<AuditKey>();
            foreach (var (id, secret) in options.AdditionalHmacKeys)
            {
                if (!string.Equals(id, options.HmacKeyId, StringComparison.Ordinal))
                {
                    retired.Add(new AuditKey(id, Encoding.UTF8.GetBytes(secret)));
                }
            }

            var currentId = string.IsNullOrEmpty(options.HmacKeyId) ? null : options.HmacKeyId;
            return new AuditKeyRing(new AuditKey(currentId, Encoding.UTF8.GetBytes(options.HmacSecretKey)), retired);
        }

        /// <summary>
        /// The keys an entry sealed with <paramref name="keyId"/> may have been authenticated with.
        /// An entry without a key id predates key rotation, so every key is a candidate.
        /// </summary>
        public IReadOnlyList<AuditKey> Candidates(string? keyId)
        {
            if (string.IsNullOrEmpty(keyId))
            {
                return _all;
            }

            return _byId.TryGetValue(keyId, out var key) ? new[] { key } : NoKeys;
        }
    }
}
