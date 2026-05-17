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
        private readonly ILogger<SmtpAnchorPublisher> _logger;

        public SmtpAnchorPublisher(TamperEvidentOptions options, ILoggerFactory loggerFactory = null)
        {
            _options = options;
            _logger = loggerFactory?.CreateLogger<SmtpAnchorPublisher>();
        }

        public async Task SendAnchorAsync(string tableName, string currentHash, int recordCount)
        {
            if (string.IsNullOrEmpty(_options.SmtpHost) || string.IsNullOrEmpty(_options.AnchorEmailTo))
            {
                _logger?.LogWarning("SMTP Host or AnchorEmailTo is not configured. Anchor will not be sent.");
                return;
            }

            var mailMessage = new MailMessage
            {
                From = new MailAddress(_options.SmtpUser),
                Subject = $"SECURITY ANCHOR - {tableName} Table",
                Body = $"Table: {tableName}\n" +
                       $"Total New Records: {recordCount}\n" +
                       $"Timestamp: {DateTime.UtcNow:O} UTC\n\n" +
                       $"Anchor Hash Key:\n{currentHash}\n\n" +
                       $"Please do not delete this email. This key will be required during the data integrity verification process."
            };

            mailMessage.To.Add(_options.AnchorEmailTo);

            using (var smtpClient = new SmtpClient(_options.SmtpHost, _options.SmtpPort))
            {
                smtpClient.Credentials = new NetworkCredential(_options.SmtpUser, _options.SmtpPassword);
                smtpClient.EnableSsl = true;

                try
                {
                    await smtpClient.SendMailAsync(mailMessage);
                    _logger?.LogInformation("Successfully sent anchor email for table {TableName}.", tableName);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to send anchor email for table {TableName}.", tableName);
                }
            }
        }
    }
}
