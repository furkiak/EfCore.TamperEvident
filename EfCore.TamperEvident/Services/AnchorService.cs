using EfCore.TamperEvident.Configuration;
using System.Net;
using System.Net.Mail;

namespace EfCore.TamperEvident.Services
{
    public class AnchorService
    {
        private readonly TamperEvidentOptions _options; 
        public AnchorService(TamperEvidentOptions options)
        {
            _options = options;
        } 
        public async Task SendAnchorEmailAsync(string tableName, string currentHash, int recordCount)
        {
 
            if (string.IsNullOrEmpty(_options.SmtpHost) || string.IsNullOrEmpty(_options.AnchorEmailTo))
                return;

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
                }
                catch (Exception)
                {
 
                }
            }
        }
    }
}