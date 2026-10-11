using System.Net;
using System.Net.Mail;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Models;
using Microsoft.Extensions.Logging;

namespace EfCore.TamperEvident.Services
{
    /// <summary>
    /// Publishes anchors as e-mails. Keep the mails in a mailbox that the database administrators cannot access.
    /// </summary>
    public class SmtpAnchorPublisher : IAnchorPublisher
    {
        private readonly TamperEvidentOptions _options;
        private readonly ILogger<SmtpAnchorPublisher>? _logger;

        /// <summary>Creates the publisher from the SMTP settings of <paramref name="options"/>.</summary>
        /// <param name="options">The options holding the SMTP settings.</param>
        /// <param name="loggerFactory">An optional logger factory.</param>
        public SmtpAnchorPublisher(TamperEvidentOptions options, ILoggerFactory? loggerFactory = null)
        {
            _options = options;
            _logger = loggerFactory?.CreateLogger<SmtpAnchorPublisher>();
        }

        /// <summary>Whether <paramref name="options"/> contains everything that is needed to send e-mails.</summary>
        /// <param name="options">The options to inspect.</param>
        public static bool IsConfigured(TamperEvidentOptions options) =>
            !string.IsNullOrWhiteSpace(options.SmtpHost)
            && !string.IsNullOrWhiteSpace(options.SmtpUser)
            && !string.IsNullOrWhiteSpace(options.AnchorEmailTo);

        /// <inheritdoc />
        public async Task PublishAsync(AuditAnchor anchor, CancellationToken cancellationToken = default)
        {
            if (!IsConfigured(_options))
            {
                throw new InvalidOperationException(
                    "SmtpHost, SmtpUser and AnchorEmailTo must be configured to send anchor e-mails.");
            }

            using var message = new MailMessage
            {
                From = new MailAddress(_options.SmtpUser!),
                Subject = $"SECURITY ANCHOR - {anchor.TableName} Table",
                Body = BuildBody(anchor)
            };
            message.To.Add(_options.AnchorEmailTo!);

            using var client = new SmtpClient(_options.SmtpHost!, _options.SmtpPort)
            {
                EnableSsl = _options.SmtpEnableSsl,
                Credentials = new NetworkCredential(_options.SmtpUser, _options.SmtpPassword)
            };

            // Failures are propagated: the dispatcher retries and logs them.
            await client.SendMailAsync(message, cancellationToken).ConfigureAwait(false);
            _logger?.LogInformation("Sent anchor e-mail for table {TableName} (sequence {Sequence}).", anchor.TableName, anchor.SequenceNumber);
        }

        internal static string BuildBody(AuditAnchor anchor) =>
            $"Table: {anchor.TableName}\n" +
            $"Sequence: {anchor.SequenceNumber}\n" +
            $"Total New Records: {anchor.RecordCount}\n" +
            $"Timestamp: {anchor.CreatedUtc.UtcDateTime:O} UTC\n\n" +
            $"Anchor Hash Key:\n{anchor.Hash}\n\n" +
            "Please do not delete this email. This key will be required during the data integrity verification process.";
    }
}
