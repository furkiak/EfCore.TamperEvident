using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EfCore.TamperEvident.Models;

namespace EfCore.TamperEvident.Services
{
    /// <summary>
    /// Publishes anchors by POSTing them as JSON to a URL (a SIEM, a Slack/Teams relay, an append-only ledger...).
    /// When a signing secret is given, the request carries an <c>X-TamperEvident-Signature: sha256=&lt;hex&gt;</c>
    /// header, the HMAC-SHA256 of the request body, so the receiver can authenticate the sender.
    /// </summary>
    public class WebhookAnchorPublisher : IAnchorPublisher
    {
        /// <summary>Name of the header that carries the body signature.</summary>
        public const string SignatureHeader = "X-TamperEvident-Signature";

        private static readonly HttpClient SharedClient = new() { Timeout = TimeSpan.FromSeconds(30) };

        private readonly Uri _url;
        private readonly HttpClient _client;
        private readonly byte[]? _signingKey;

        /// <summary>Creates the publisher.</summary>
        /// <param name="url">The endpoint that receives the anchors.</param>
        /// <param name="signingSecret">Optional secret used to sign the request body.</param>
        /// <param name="httpClient">An optional client; a shared one is used by default.</param>
        public WebhookAnchorPublisher(Uri url, string? signingSecret = null, HttpClient? httpClient = null)
        {
            _url = url ?? throw new ArgumentNullException(nameof(url));
            _client = httpClient ?? SharedClient;
            _signingKey = string.IsNullOrEmpty(signingSecret) ? null : Encoding.UTF8.GetBytes(signingSecret);
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
                var signature = Convert.ToHexString(HMACSHA256.HashData(_signingKey, body)).ToLowerInvariant();
                request.Headers.TryAddWithoutValidation(SignatureHeader, "sha256=" + signature);
            }

            using var response = await _client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
        }
    }
}
