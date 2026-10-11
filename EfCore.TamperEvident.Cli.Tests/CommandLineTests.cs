using System.Text.Json;
using EfCore.TamperEvident.Services;

namespace EfCore.TamperEvident.Cli.Tests
{
    /// <summary>
    /// Runs the <c>tamper-evident</c> tool the way an auditor would, and checks its exit codes and output.
    /// The tests share the console, so they must not run in parallel (there is only one test class).
    /// </summary>
    public sealed class CommandLineTests(BundleFixture bundle) : IClassFixture<BundleFixture>
    {
        private const string Intact = "Intact.";

        [Fact]
        public async Task Verify_IntactBundle_ExitsWithZero()
        {
            var result = await RunAsync("verify", bundle.Bundle, "--key-file", bundle.KeyFile);

            Assert.Equal(0, result.ExitCode);
            Assert.Contains(Intact, result.Output, StringComparison.Ordinal);
            Assert.Contains("Customers", result.Output, StringComparison.Ordinal);
            Assert.Contains("authorized redaction", result.Output, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Verify_KeyFromStandardInput_IsAccepted()
        {
            var result = await RunWithInputAsync(BundleFixture.Secret + Environment.NewLine, "verify", bundle.Bundle, "--key-stdin");

            Assert.Equal(0, result.ExitCode);
        }

        [Fact]
        public async Task Verify_KeyFromEnvironmentVariable_IsAccepted()
        {
            var variable = "TE_CLI_TEST_KEY_" + Guid.NewGuid().ToString("N");
            Environment.SetEnvironmentVariable(variable, BundleFixture.Secret);
            try
            {
                var result = await RunAsync("verify", bundle.Bundle, "--key-env", variable);
                Assert.Equal(0, result.ExitCode);
            }
            finally
            {
                Environment.SetEnvironmentVariable(variable, null);
            }
        }

        [Fact]
        public async Task Verify_Json_ReportsEveryTable()
        {
            var result = await RunAsync("verify", bundle.Bundle, "--key-file", bundle.KeyFile, "--json");

            Assert.Equal(0, result.ExitCode);
            using var json = JsonDocument.Parse(result.Output);
            Assert.True(json.RootElement.GetProperty("isValid").GetBoolean());
            var table = Assert.Single(json.RootElement.GetProperty("tables").EnumerateArray());
            Assert.Equal("Customers", table.GetProperty("table").GetString());
            Assert.Equal(nameof(AuditFailureKind.None), table.GetProperty("result").GetString());
            Assert.True(table.GetProperty("redactedRecords").GetInt64() > 0);
            Assert.Equal(table.GetProperty("headSequence").GetInt64(), json.RootElement.GetProperty("recordsChecked").GetInt64());
        }

        [Fact]
        public async Task Verify_ChangedEntry_ExitsWithOne()
        {
            var tampered = bundle.PathFor("tampered-" + Guid.NewGuid().ToString("N") + ".json");
            var text = await File.ReadAllTextAsync(bundle.Bundle);
            Assert.Contains("Customer 3", text, StringComparison.Ordinal);
            await File.WriteAllTextAsync(tampered, text.Replace("Customer 3", "Customer 9", StringComparison.Ordinal));

            var result = await RunAsync("verify", tampered, "--key-file", bundle.KeyFile, "--json");

            Assert.Equal(1, result.ExitCode);
            using var json = JsonDocument.Parse(result.Output);
            Assert.False(json.RootElement.GetProperty("isValid").GetBoolean());
            var table = Assert.Single(json.RootElement.GetProperty("tables").EnumerateArray());
            Assert.Equal(nameof(AuditFailureKind.DataManipulated), table.GetProperty("result").GetString());
        }

        [Fact]
        public async Task Verify_WrongKey_ExitsWithOne()
        {
            var wrongKey = bundle.PathFor("wrong-key-" + Guid.NewGuid().ToString("N") + ".txt");
            await File.WriteAllTextAsync(wrongKey, "another-secret-0123456789-abcdefghijklmnop");

            var result = await RunAsync("verify", bundle.Bundle, "--key-file", wrongKey);

            Assert.Equal(1, result.ExitCode);
            Assert.DoesNotContain(Intact, result.Output, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Verify_AnchorFile_IsMatched()
        {
            Assert.NotEmpty(FileAnchorPublisher.ReadAnchors(bundle.Anchors));

            var result = await RunAsync("verify", bundle.Bundle, "--key-file", bundle.KeyFile, "--anchors", bundle.Anchors, "--json");

            Assert.Equal(0, result.ExitCode);
            using var json = JsonDocument.Parse(result.Output);
            var table = Assert.Single(json.RootElement.GetProperty("tables").EnumerateArray());
            Assert.Equal(FileAnchorPublisher.ReadAnchors(bundle.Anchors).Count, table.GetProperty("anchorsMatched").GetInt32());
        }

        [Fact]
        public async Task Verify_AnchorsInAnEmail_AreFoundAndMatched()
        {
            var anchor = FileAnchorPublisher.ReadAnchors(bundle.Anchors)[0];
            var mail = bundle.PathFor("mail-" + Guid.NewGuid().ToString("N") + ".txt");
            await File.WriteAllTextAsync(mail, $"Subject: Audit anchor\n\nTable: {anchor.TableName}\nHash: {anchor.Hash.ToUpperInvariant()}\n");

            var result = await RunAsync("verify", bundle.Bundle, "--key-file", bundle.KeyFile, "--anchors", mail, "--json");

            Assert.Equal(0, result.ExitCode);
            using var json = JsonDocument.Parse(result.Output);
            Assert.Equal(1, Assert.Single(json.RootElement.GetProperty("tables").EnumerateArray()).GetProperty("anchorsMatched").GetInt32());
        }

        [Fact]
        public async Task Verify_AnchorThatDoesNotOccur_ExitsWithOne()
        {
            var mail = bundle.PathFor("forged-" + Guid.NewGuid().ToString("N") + ".txt");
            await File.WriteAllTextAsync(mail, "Hash: " + new string('a', 64));

            var result = await RunAsync("verify", bundle.Bundle, "--key-file", bundle.KeyFile, "--anchors", mail);

            Assert.Equal(1, result.ExitCode);
            Assert.Contains("does not occur in the bundle", result.Output, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Verify_TruncatedBundle_ExitsWithTwo()
        {
            var truncated = bundle.PathFor("truncated-" + Guid.NewGuid().ToString("N") + ".json");
            var bytes = await File.ReadAllBytesAsync(bundle.Bundle);
            await File.WriteAllBytesAsync(truncated, bytes.AsSpan(0, bytes.Length / 2).ToArray());

            var result = await RunAsync("verify", truncated, "--key-file", bundle.KeyFile);

            Assert.Equal(2, result.ExitCode);
            Assert.Contains("not valid JSON", result.Error, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Verify_MissingKey_ExitsWithTwo()
        {
            var result = await RunAsync("verify", bundle.Bundle, "--key-env", "TE_CLI_TEST_UNSET_" + Guid.NewGuid().ToString("N"));

            Assert.Equal(2, result.ExitCode);
            Assert.Contains("never accepted on the command line", result.Error, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Verify_KeyOnTheCommandLine_IsRefused()
        {
            var result = await RunAsync("verify", bundle.Bundle, "--key-file", bundle.KeyFile, "--key", BundleFixture.Secret);

            Assert.Equal(2, result.ExitCode);
            Assert.Contains("Unknown option --key", result.Error, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Verify_MissingFile_ExitsWithTwo()
        {
            var result = await RunAsync("verify", bundle.PathFor("does-not-exist.json"), "--key-file", bundle.KeyFile);

            Assert.Equal(2, result.ExitCode);
        }

        [Fact]
        public async Task Inspect_SummarizesWithoutTheKey()
        {
            var result = await RunAsync("inspect", bundle.Bundle, "--json");

            Assert.Equal(0, result.ExitCode);
            using var json = JsonDocument.Parse(result.Output);
            Assert.Equal(AuditExporter.EvidenceFormat, json.RootElement.GetProperty("format").GetInt32());
            var table = Assert.Single(json.RootElement.GetProperty("tables").EnumerateArray());
            Assert.Equal("Customers", table.GetProperty("table").GetString());
            Assert.Equal(table.GetProperty("headSequence").GetInt64(), table.GetProperty("entries").GetInt64());
        }

        [Fact]
        public async Task KeyGen_PrintsAStrongRandomKey()
        {
            var first = await RunAsync("keygen");
            var second = await RunAsync("keygen", "--bytes", "64");

            Assert.Equal(0, first.ExitCode);
            Assert.Equal(48, Convert.FromBase64String(first.Output.Trim()).Length);
            Assert.Equal(64, Convert.FromBase64String(second.Output.Trim()).Length);
            Assert.NotEqual(first.Output, second.Output);
        }

        [Theory]
        [InlineData("keygen", "--bytes", "8")]
        [InlineData("explode")]
        [InlineData("verify")]
        public async Task InvalidUsage_ExitsWithTwo(params string[] args)
        {
            var result = await RunAsync(args);

            Assert.Equal(2, result.ExitCode);
            Assert.StartsWith("tamper-evident: ", result.Error, StringComparison.Ordinal);
        }

        [Fact]
        public async Task HelpAndVersion_ExitWithZero()
        {
            var help = await RunAsync("--help");
            var version = await RunAsync("--version");

            Assert.Equal(0, help.ExitCode);
            Assert.Contains("EXIT CODES", help.Output, StringComparison.Ordinal);
            Assert.Equal(0, version.ExitCode);
            Assert.Matches(@"^\d+\.\d+\.\d+", version.Output);
        }

        private static Task<CliResult> RunAsync(params string[] args) => RunWithInputAsync(string.Empty, args);

        private static async Task<CliResult> RunWithInputAsync(string input, params string[] args)
        {
            var (previousIn, previousOut, previousError) = (Console.In, Console.Out, Console.Error);
            using var output = new StringWriter();
            using var error = new StringWriter();
            Console.SetIn(new StringReader(input));
            Console.SetOut(output);
            Console.SetError(error);
            try
            {
                var exitCode = await Program.Main(args);
                return new CliResult(exitCode, output.ToString(), error.ToString());
            }
            finally
            {
                Console.SetIn(previousIn);
                Console.SetOut(previousOut);
                Console.SetError(previousError);
            }
        }

        private sealed record CliResult(int ExitCode, string Output, string Error);
    }
}
