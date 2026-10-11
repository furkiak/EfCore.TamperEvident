using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EfCore.TamperEvident.Internal;
using EfCore.TamperEvident.Models;

namespace EfCore.TamperEvident.Services
{
    /// <summary>
    /// Publishes anchors by POSTing them as JSON to a URL (a SIEM, a Slack/Teams relay, an append-only ledger...).
    /// </summary>
    /// <remarks>
    /// When a signing secret is given, the request carries an <c>X-TamperEvident-Signature: t=&lt;unix time&gt;,v1=&lt;hex&gt;</c>
    /// header: the HMAC-SHA256 of <c>"&lt;unix time&gt;." + body</c>. Because the time is signed too, a captured request cannot be
    /// replayed later. Receivers check it with <see cref="VerifySignature"/>.
    /// </remarks>
    public class WebhookAnchorPublisher : IAnchorPublisher
    {
        /// <summary>Name of the header that carries the body signature.</summary>
        public const string SignatureHeader = "X-TamperEvident-Signature";

        private static readonly HttpClient SharedClient = new() { Timeout = TimeSpan.FromSeconds(30) };

        private readonly Uri _url;
        private readonly HttpClient _client;
        private readonly byte[]? _signingKey;
        private readonly TimeProvider _clock;

        /// <summary>Creates the publisher.</summary>
        /// <param name="url">The endpoint that receives the anchors.</param>
        /// <param name="signingSecret">Optional secret used to sign the request body.</param>
        /// <param name="httpClient">An optional client; a shared one is used by default.</param>
        /// <param name="timeProvider">The clock used for the signature timestamp.</param>
        public WebhookAnchorPublisher(Uri url, string? signingSecret = null, HttpClient? httpClient = null, TimeProvider? timeProvider = null)
        {
            _url = url ?? throw new ArgumentNullException(nameof(url));
            _client = httpClient ?? SharedClient;
            _signingKey = string.IsNullOrEmpty(signingSecret) ? null : Encoding.UTF8.GetBytes(signingSecret);
            _clock = timeProvider ?? TimeProvider.System;
        }

        /// <inheritdoc />
        public async Task PublishAsync(AuditAnchor anchor, CancellationToken cancellationToken = default)
        {
            var body = JsonSerializer.SerializeToUtf8Bytes(new
            {
                tableName = anchor.TableName,
                hash = anchor.Hash,
                sequenceNumber = anchor.SequenceNumber,
                recordCount = anchor.RecordCount,
                createdUtc = anchor.CreatedUtc.UtcDateTime
            });

            using var content = new ByteArrayContent(body);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            using var request = new HttpRequestMessage(HttpMethod.Post, _url) { Content = content };
            request.Headers.TryAddWithoutValidation("X-TamperEvident-Table", anchor.TableName);

            if (_signingKey is not null)
            {
                var timestamp = _clock.GetUtcNow().ToUnixTimeSeconds();
                request.Headers.TryAddWithoutValidation(SignatureHeader,
                    "t=" + timestamp.ToString(CultureInfo.InvariantCulture) + ",v1=" + Hex.ToLower(Sign(_signingKey, timestamp, body)));
            }

            using var response = await _client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
        }

        /// <summary>
        /// Checks the <see cref="SignatureHeader"/> of a received anchor: the signature must match the body and the
        /// signing time must lie within <paramref name="tolerance"/> of now. Compare in constant time, before parsing the body.
        /// </summary>
        /// <param name="signatureHeader">The value of the <c>X-TamperEvident-Signature</c> header.</param>
        /// <param name="body">The raw request body.</param>
        /// <param name="signingSecret">The secret shared with the publisher.</param>
        /// <param name="tolerance">How old (or how far in the future) a signature may be. Defaults to five minutes.</param>
        /// <param name="timeProvider">The clock (for tests).</param>
        /// <returns><c>true</c> when the request is authentic and fresh.</returns>
        public static bool VerifySignature(
            string? signatureHeader, ReadOnlySpan<byte> body, string signingSecret, TimeSpan? tolerance = null, TimeProvider? timeProvider = null)
        {
            ArgumentException.ThrowIfNullOrEmpty(signingSecret);
            if (string.IsNullOrEmpty(signatureHeader))
            {
                return false;
            }

            long? timestamp = null;
            string? signature = null;
            foreach (var part in signatureHeader.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                if (part.StartsWith("t=", StringComparison.Ordinal)
                    && long.TryParse(part.AsSpan(2), NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
                {
                    timestamp = parsed;
                }
                else if (part.StartsWith("v1=", StringComparison.Ordinal))
                {
                    signature = part[3..];
                }
            }

            Span<byte> provided = stackalloc byte[32];
            if (timestamp is null || signature is null || !Hex.TryDecode(signature.AsSpan(), provided))
            {
                return false;
            }

            var age = (timeProvider ?? TimeProvider.System).GetUtcNow() - DateTimeOffset.FromUnixTimeSeconds(timestamp.Value);
            if (age.Duration() > (tolerance ?? TimeSpan.FromMinutes(5)))
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(Sign(Encoding.UTF8.GetBytes(signingSecret), timestamp.Value, body), provided);
        }

        private static byte[] Sign(byte[] key, long timestamp, ReadOnlySpan<byte> body)
        {
            var prefix = Encoding.ASCII.GetBytes(timestamp.ToString(CultureInfo.InvariantCulture) + ".");
            var payload = new byte[prefix.Length + body.Length];
            prefix.CopyTo(payload, 0);
            body.CopyTo(payload.AsSpan(prefix.Length));
            return HMACSHA256.HashData(key, payload);
        }
    }
}
