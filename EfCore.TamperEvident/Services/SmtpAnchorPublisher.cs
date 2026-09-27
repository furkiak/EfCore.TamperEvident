using EfCore.TamperEvident.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace EfCore.TamperEvident.Services
{
    public class SmtpAnchorPublisher : IAnchorPublisher
    {
        private readonly TamperEvidentOptions _options;
        private readonly ILogger<SmtpAnchorPublisher>? _logger;

        public SmtpAnchorPublisher(TamperEvidentOptions options, ILoggerFactory? loggerFactory = null)
        {
            _options = options;
            _logger = loggerFactory?.CreateLogger<SmtpAnchorPublisher>();
        }

        public Task SendAnchorAsync(string tableName, string currentHash, int recordCount) =>
            SendAnchorAsync(new AnchorDelivery(Guid.NewGuid(), tableName, currentHash, recordCount, DateTime.UtcNow));

        public async Task SendAnchorAsync(AnchorDelivery anchor, CancellationToken cancellationToken = default)
        {
            _options.Validate();
            if (string.IsNullOrEmpty(_options.SmtpHost) || string.IsNullOrEmpty(_options.AnchorEmailTo) || string.IsNullOrEmpty(_options.SmtpUser))
            {
                throw new InvalidOperationException("SMTP Host, User, or AnchorEmailTo is not configured; the anchor remains pending.");
            }

            using var mailMessage = new MailMessage
            {
                From = new MailAddress(_options.SmtpUser),
                BodyEncoding = System.Text.Encoding.UTF8,
                BodyTransferEncoding = System.Net.Mime.TransferEncoding.Base64,
                Subject = $"SECURITY ANCHOR - {anchor.TableName} Table",
                Body = $"Anchor ID: {anchor.Id:D}\n" +
                       $"Table: {anchor.TableName}\n" +
                       $"Total New Records: {anchor.RecordCount}\n" +
                       $"Created: {anchor.CreatedAtUtc:O}\n\n" +
                       $"Anchor Hash (not the HMAC secret):\n{anchor.AnchorHash}\n\n" +
                       $"Retain this anchor hash outside the audited database's administrative boundary. SMTP acceptance alone does not prove independent retention."
            };

            mailMessage.To.Add(_options.AnchorEmailTo);
            mailMessage.Headers.Add("X-Audit-Anchor-Id", anchor.Id.ToString("D"));
            mailMessage.Headers.Add("X-Audit-Anchor-Hash", anchor.AnchorHash);

            using (var smtpClient = new SmtpClient(_options.SmtpHost, _options.SmtpPort))
            {
                smtpClient.Credentials = new NetworkCredential(_options.SmtpUser, _options.SmtpPassword);
                smtpClient.EnableSsl = !_options.AllowUnencryptedLoopbackSmtp;
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(_options.SmtpTimeoutSeconds));

                try
                {
                    await smtpClient.SendMailAsync(mailMessage, timeout.Token);
                    _logger?.LogInformation("SMTP accepted anchor {AnchorId}.", anchor.Id);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning("SMTP failed for anchor {AnchorId}: {ErrorType}.", anchor.Id, ex.GetType().Name);
                    throw;
                }
            }
        }
    }
}
