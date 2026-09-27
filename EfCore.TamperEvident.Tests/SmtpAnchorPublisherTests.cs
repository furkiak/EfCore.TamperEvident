using System.Net.Mail;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Services;

namespace EfCore.TamperEvident.Tests;

public sealed class SmtpAnchorPublisherTests
{
    [Fact]
    public void PlaintextSmtpCannotBeEnabledForARemoteOrDnsHost()
    {
        foreach (var host in new[] { "smtp.example.test", "localhost", "192.0.2.1", "0.0.0.0" })
            Assert.Throws<InvalidOperationException>(() => new TamperEvidentOptions
            {
                HmacSecretKey = TestKeys.Key, SmtpHost = host, AllowUnencryptedLoopbackSmtp = true
            }.Validate());
        Assert.False(new TamperEvidentOptions().AllowUnencryptedLoopbackSmtp);
    }

    [Fact]
    public async Task DefaultTlsRejectsSinkWithoutStartTls()
    {
        await using var sink = new LoopbackSmtpSink();
        var options = LocalOptions(sink.Port);
        options.AllowUnencryptedLoopbackSmtp = false;
        await Assert.ThrowsAsync<SmtpException>(() => new SmtpAnchorPublisher(options)
            .SendAnchorAsync(new AnchorDelivery(Guid.NewGuid(), "Example", "v2:test", 1, DateTime.UtcNow)));
        Assert.Empty(sink.Messages);
    }

    internal static TamperEvidentOptions LocalOptions(int port) => new()
    {
        HmacSecretKey = TestKeys.Key, SmtpHost = "127.0.0.1", SmtpPort = port,
        SmtpUser = "audit@example.test", AnchorEmailTo = "receiver@example.test",
        AllowUnencryptedLoopbackSmtp = true, SmtpTimeoutSeconds = 5, AnchorThreshold = 1
    };
}
