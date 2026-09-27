using System.Net;
using System.Net.Sockets;
using System.Text;

namespace EfCore.TamperEvident.Tests;

// An actual TCP/SMTP receiver. It never binds to a non-loopback interface or forwards mail.
internal sealed class LoopbackSmtpSink : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _accept;
    private readonly List<Task> _clients = [];
    private readonly List<string> _messages = [];
    public int Port { get; }
    public IReadOnlyList<string> Messages { get { lock (_messages) return _messages.ToArray(); } }

    public LoopbackSmtpSink(int port = 0)
    {
        _listener = new TcpListener(IPAddress.Loopback, port);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _accept = AcceptAsync();
    }

    public static int ReserveClosedPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public static string DecodeBody(string message)
    {
        var parts = new System.Text.RegularExpressions.Regex(@"\r?\n\r?\n").Split(message, 2);
        if (parts.Length != 2 || !parts[0].Contains("Content-Transfer-Encoding: base64", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Expected a base64 UTF-8 mail body.");
        return Encoding.UTF8.GetString(Convert.FromBase64String(parts[1]));
    }

    private async Task AcceptAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
                _clients.Add(HandleAsync(await _listener.AcceptTcpClientAsync(_stop.Token)));
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (SocketException) when (_stop.IsCancellationRequested) { }
    }

    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
            using var writer = new StreamWriter(stream, Encoding.ASCII, leaveOpen: true)
                { AutoFlush = true, NewLine = "\r\n" };
            try
            {
                await writer.WriteLineAsync("220 loopback.test ESMTP");
                while (await reader.ReadLineAsync(timeout.Token) is { } command)
                {
                    if (command.StartsWith("EHLO", StringComparison.OrdinalIgnoreCase))
                        await writer.WriteAsync("250-loopback.test\r\n250 SIZE 65536\r\n");
                    else if (command.StartsWith("HELO", StringComparison.OrdinalIgnoreCase) ||
                             command.StartsWith("MAIL FROM", StringComparison.OrdinalIgnoreCase) ||
                             command.StartsWith("RCPT TO", StringComparison.OrdinalIgnoreCase) ||
                             command is "RSET" or "NOOP")
                        await writer.WriteLineAsync("250 OK");
                    else if (command == "DATA")
                    {
                        await writer.WriteLineAsync("354 End with <CRLF>.<CRLF>");
                        var message = new StringBuilder();
                        while (await reader.ReadLineAsync(timeout.Token) is { } line && line != ".")
                            message.AppendLine(line.StartsWith("..", StringComparison.Ordinal) ? line[1..] : line);
                        lock (_messages) _messages.Add(message.ToString());
                        await writer.WriteLineAsync("250 Accepted by local sink");
                    }
                    else if (command == "QUIT")
                    {
                        await writer.WriteLineAsync("221 Bye");
                        break;
                    }
                    else await writer.WriteLineAsync("502 Unsupported command");
                }
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
            catch (IOException) { }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        _listener.Stop();
        await _accept;
        await Task.WhenAll(_clients);
        _stop.Dispose();
    }
}
