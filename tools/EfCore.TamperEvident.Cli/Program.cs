using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Services;

namespace EfCore.TamperEvident.Cli
{
    /// <summary>
    /// <c>tamper-evident</c>: verifies and summarizes evidence bundles, and generates secret keys.
    /// Exit codes: 0 everything intact, 1 tampering detected, 2 invalid input or usage.
    /// </summary>
    public static partial class Program
    {
        private const string DefaultKeyVariable = "TAMPER_EVIDENT_KEY";

        private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

        private static readonly string[] InspectHeader = { "TABLE", "ENTRIES", "HEAD", "FROM", "TO", "USERS", "ACTIONS", "STORED VERDICT" };

        [GeneratedRegex("(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")]
        private static partial Regex HashPattern();

        public static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            try
            {
                return args switch
                {
                    [] or ["-h" or "--help" or "help", ..] => Help(),
                    ["-v" or "--version" or "version", ..] => Version(),
                    ["verify", .. var rest] => await VerifyAsync(new Arguments(rest)),
                    ["inspect", .. var rest] => await InspectAsync(new Arguments(rest)),
                    ["keygen", .. var rest] => KeyGen(new Arguments(rest)),
                    _ => Fail($"Unknown command '{args[0]}'. Run 'tamper-evident --help'.")
                };
            }
            catch (UsageException ex)
            {
                return Fail(ex.Message);
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or InvalidOperationException or UnauthorizedAccessException)
            {
                return Fail(ex.Message);
            }
        }

        // ------------------------------------------------------------------------------------------------------- verify

        private static async Task<int> VerifyAsync(Arguments args)
        {
            var path = args.Positional(0, "the evidence bundle to verify");
            var json = args.Flag("--json");
            var options = new TamperEvidentOptions { HmacSecretKey = ReadKey(args), HmacKeyId = args.Option("--key-id") };
            foreach (var retired in args.Options("--retired-key"))
            {
                var separator = retired.IndexOf('=', StringComparison.Ordinal);
                if (separator <= 0)
                {
                    throw new UsageException("--retired-key expects <key id>=env:<VARIABLE> or <key id>=file:<PATH>.");
                }

                options.AdditionalHmacKeys[retired[..separator]] = ReadSource(retired[(separator + 1)..], "--retired-key");
            }

            var anchorFiles = args.Options("--anchors");
            options.Validate();
            args.EnsureConsumed();

            var (assigned, loose) = ReadAnchors(anchorFiles);
            var unmatched = new List<string>();
            if (loose.Count > 0)
            {
                // Hashes from e-mails or notes do not say which table they belong to: look them up first.
                await using var scan = File.OpenRead(path);
                var summary = await AuditEvidence.SummarizeAsync(scan, loose, CancellationToken.None);
                foreach (var hash in loose)
                {
                    if (summary.Located.TryGetValue(hash, out var table))
                    {
                        assigned.TryAdd(table, new List<string>());
                        assigned[table].Add(hash);
                    }
                    else
                    {
                        unmatched.Add(hash);
                    }
                }
            }

            await using var stream = File.OpenRead(path);
            var report = await AuditEvidence.VerifyBundleAsync(
                stream, options, assigned.ToDictionary(p => p.Key, p => (IEnumerable<string>)p.Value, StringComparer.Ordinal));
            var valid = report.IsValid && unmatched.Count == 0;

            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    isValid = valid,
                    message = unmatched.Count > 0 ? $"{unmatched.Count} anchors do not occur in the bundle." : report.Message,
                    recordsChecked = report.RecordsChecked,
                    unmatchedAnchors = unmatched,
                    tables = report.Tables.Select(t => new
                    {
                        table = t.TableName,
                        isValid = t.IsValid,
                        result = t.Failure.ToString(),
                        message = t.Message,
                        recordsChecked = t.RecordsChecked,
                        anchorsMatched = t.AnchorsMatched,
                        redactedRecords = t.RedactedRecords,
                        failedSequence = t.FailedSequence,
                        headSequence = t.HeadSequence,
                        headHash = t.HeadHash
                    })
                }, Indented));
                return valid ? 0 : 1;
            }

            var color = new Style();
            Console.WriteLine();
            Console.WriteLine($"  {color.Bold("Evidence bundle")}  {Path.GetFileName(path)}");
            Console.WriteLine();
            var width = Math.Max(5, report.Tables.Select(t => (t.TableName ?? string.Empty).Length).DefaultIfEmpty(5).Max());
            foreach (var table in report.Tables)
            {
                var name = (table.TableName ?? string.Empty).PadRight(width);
                if (table.IsValid)
                {
                    var details = new List<string> { Plural(table.RecordsChecked, "entry", "entries") };
                    if (table.AnchorsMatched > 0)
                    {
                        details.Add(Plural(table.AnchorsMatched, "anchor matched", "anchors matched"));
                    }

                    if (table.RedactedRecords > 0)
                    {
                        details.Add(Plural(table.RedactedRecords, "authorized redaction", "authorized redactions"));
                    }

                    Console.WriteLine($"  {color.Green("✔")} {name}  {string.Join(" · ", details)}  {color.Dim($"head #{table.HeadSequence}")}");
                }
                else
                {
                    var where = table.FailedSequence is { } sequence ? $" at entry #{sequence}" : string.Empty;
                    Console.WriteLine($"  {color.Red("✘")} {name}  {color.Red(table.Failure + where)}");
                    Console.WriteLine($"    {color.Dim(table.Message)}");
                }
            }

            foreach (var hash in unmatched)
            {
                Console.WriteLine($"  {color.Red("✘")} anchor {hash[..12]}…  {color.Red("does not occur in the bundle: the history was rewritten")}");
            }

            Console.WriteLine();
            Console.WriteLine(valid
                ? "  " + color.Green(color.Bold("Intact.")) + $" {Plural(report.RecordsChecked, "entry", "entries")} in {Plural(report.Tables.Count, "table", "tables")} verified."
                : "  " + color.Red(color.Bold(report.IsValid
                    ? $"TAMPERING SUSPECTED: {Plural(unmatched.Count, "anchor does", "anchors do")} not occur in the bundle."
                    : report.Message)));
            Console.WriteLine();
            return valid ? 0 : 1;
        }

        private static string ReadKey(Arguments args)
        {
            var sources = new[] { args.Option("--key-env"), args.Option("--key-file"), args.Flag("--key-stdin") ? "stdin" : null }
                .Count(s => s is not null);
            if (sources > 1)
            {
                throw new UsageException("Use only one of --key-env, --key-file and --key-stdin.");
            }

            if (args.Option("--key-file") is { } file)
            {
                return ReadSource("file:" + file, "--key-file");
            }

            if (args.Flag("--key-stdin"))
            {
                return Console.In.ReadLine()?.Trim() ?? throw new UsageException("No key was received on standard input.");
            }

            return ReadSource("env:" + (args.Option("--key-env") ?? DefaultKeyVariable), "--key-env");
        }

        private static string ReadSource(string source, string option)
        {
            if (source.StartsWith("env:", StringComparison.Ordinal))
            {
                var name = source[4..];
                return Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
                    ? value
                    : throw new UsageException($"The environment variable {name} is not set ({option}). The key is never accepted on the command line.");
            }

            if (source.StartsWith("file:", StringComparison.Ordinal))
            {
                return File.ReadAllText(source[5..]).Trim();
            }

            throw new UsageException($"{option} expects env:<VARIABLE> or file:<PATH>.");
        }

        private static (Dictionary<string, List<string>> Assigned, List<string> Loose) ReadAnchors(IEnumerable<string> files)
        {
            var assigned = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            var loose = new List<string>();
            foreach (var file in files)
            {
                try
                {
                    // A file written by FileAnchorPublisher knows the table of every anchor.
                    foreach (var anchor in FileAnchorPublisher.ReadAnchors(file))
                    {
                        assigned.TryAdd(anchor.TableName, new List<string>());
                        assigned[anchor.TableName].Add(anchor.Hash);
                    }
                }
                catch (Exception ex) when (ex is JsonException or InvalidDataException or NotSupportedException)
                {
                    // Anything else (saved e-mails, notes): every 64 character hex string is an anchor.
                    loose.AddRange(HashPattern().Matches(File.ReadAllText(file)).Select(m => m.Value.ToLowerInvariant()));
                }
            }

            return (assigned, loose.Distinct().ToList());
        }

        // ------------------------------------------------------------------------------------------------------ inspect

        private static async Task<int> InspectAsync(Arguments args)
        {
            var path = args.Positional(0, "the evidence bundle to inspect");
            var json = args.Flag("--json");
            args.EnsureConsumed();

            await using var stream = File.OpenRead(path);
            var summary = await AuditEvidence.SummarizeAsync(stream, null, CancellationToken.None);

            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    format = summary.Format,
                    generatedUtc = summary.GeneratedUtc,
                    generator = summary.Generator,
                    tables = summary.Tables.Select(t => new
                    {
                        table = t.Table,
                        entries = t.Entries,
                        headSequence = t.HeadSequence,
                        firstEntryUtc = t.FirstEntryUtc,
                        lastEntryUtc = t.LastEntryUtc,
                        users = t.Users,
                        actions = t.Actions,
                        storedResult = t.StoredResult
                    })
                }, Indented));
                return 0;
            }

            var color = new Style();
            Console.WriteLine();
            Console.WriteLine($"  {color.Bold("Evidence bundle")}  {Path.GetFileName(path)}  {color.Dim($"format {summary.Format}, {summary.Generator}, generated {summary.GeneratedUtc:u}")}");
            Console.WriteLine();
            var rows = new List<string[]> { InspectHeader };
            rows.AddRange(summary.Tables.Select(t => new[]
            {
                t.Table,
                t.Entries.ToString("N0", CultureInfo.InvariantCulture),
                t.HeadSequence is { } head ? "#" + head.ToString(CultureInfo.InvariantCulture) : "-",
                t.FirstEntryUtc?.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) ?? "-",
                t.LastEntryUtc?.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) ?? "-",
                t.Users.ToString(CultureInfo.InvariantCulture),
                string.Join(" ", t.Actions.Select(a => $"{a.Key}:{a.Value}")),
                t.StoredResult ?? "-"
            }));
            var widths = Enumerable.Range(0, rows[0].Length).Select(c => rows.Max(r => r[c].Length)).ToArray();
            for (var i = 0; i < rows.Count; i++)
            {
                var line = string.Join("  ", rows[i].Select((cell, c) => cell.PadRight(widths[c])));
                Console.WriteLine("  " + (i == 0 ? color.Dim(line) : line));
            }

            Console.WriteLine();
            Console.WriteLine(color.Dim("  The stored verdict is what the exporting system claimed. Run 'tamper-evident verify' to check it yourself."));
            Console.WriteLine();
            return 0;
        }

        // ------------------------------------------------------------------------------------------------------- keygen

        private static int KeyGen(Arguments args)
        {
            var bytes = int.TryParse(args.Option("--bytes") ?? "48", NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ? parsed : -1;
            args.EnsureConsumed();
            if (bytes is < 24 or > 1024)
            {
                throw new UsageException("--bytes must be between 24 and 1024.");
            }

            Console.WriteLine(Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)));
            return 0;
        }

        // ---------------------------------------------------------------------------------------------------- the rest

        private static int Help()
        {
            Console.WriteLine($"""
                tamper-evident {CurrentVersion} - verify EfCore.TamperEvident evidence bundles

                USAGE
                  tamper-evident verify <bundle.json> [options]   Recompute every hash, link, redaction and signed chain head
                  tamper-evident inspect <bundle.json> [--json]   Summarize a bundle without verifying it
                  tamper-evident keygen [--bytes 48]              Print a new random secret key (base64)

                VERIFY OPTIONS
                  --key-env <VARIABLE>          Read the secret from an environment variable (default: {DefaultKeyVariable})
                  --key-file <PATH>             Read the secret from a file
                  --key-stdin                   Read the secret from the first line of standard input
                  --key-id <ID>                 The key id of the secret (when key rotation is used)
                  --retired-key <ID>=env:<VAR>  A retired key that older entries were sealed with (repeatable; also file:<PATH>)
                  --anchors <FILE>              Anchors received outside of the database (repeatable): a file written by
                                                FileAnchorPublisher, or any text such as saved anchor e-mails
                  --json                        Print the result as JSON

                The secret is never accepted on the command line, so it cannot end up in the shell history.

                EXIT CODES
                  0  intact    1  tampering detected    2  invalid input
                """);
            return 0;
        }

        private static int Version()
        {
            Console.WriteLine(CurrentVersion);
            return 0;
        }

        private static string CurrentVersion =>
            typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "2.0.0";

        private static int Fail(string message)
        {
            Console.Error.WriteLine("tamper-evident: " + message);
            return 2;
        }

        private static string Plural(long count, string one, string many) =>
            count.ToString("N0", CultureInfo.InvariantCulture) + " " + (count == 1 ? one : many);

        private sealed class UsageException(string message) : Exception(message);

        /// <summary>A minimal parser: positional values, <c>--flag</c> and repeatable <c>--option value</c>.</summary>
        private sealed class Arguments
        {
            private readonly List<string> _positional = new();
            private readonly List<(string Name, string? Value)> _named = new();
            private readonly HashSet<string> _consumed = new(StringComparer.Ordinal);

            private static readonly HashSet<string> Flags = new(StringComparer.Ordinal) { "--json", "--key-stdin" };

            public Arguments(string[] args)
            {
                for (var i = 0; i < args.Length; i++)
                {
                    if (!args[i].StartsWith("--", StringComparison.Ordinal))
                    {
                        _positional.Add(args[i]);
                    }
                    else if (Flags.Contains(args[i]))
                    {
                        _named.Add((args[i], null));
                    }
                    else if (i + 1 < args.Length)
                    {
                        _named.Add((args[i], args[++i]));
                    }
                    else
                    {
                        throw new UsageException($"{args[i]} needs a value.");
                    }
                }
            }

            public string Positional(int index, string what)
            {
                _consumed.Add("#" + index.ToString(CultureInfo.InvariantCulture));
                return index < _positional.Count ? _positional[index] : throw new UsageException($"Missing {what}.");
            }

            public bool Flag(string name)
            {
                _consumed.Add(name);
                return _named.Any(n => n.Name == name);
            }

            public string? Option(string name)
            {
                _consumed.Add(name);
                return _named.LastOrDefault(n => n.Name == name).Value;
            }

            public List<string> Options(string name)
            {
                _consumed.Add(name);
                return _named.Where(n => n.Name == name && n.Value is not null).Select(n => n.Value!).ToList();
            }

            public void EnsureConsumed()
            {
                if (_named.FirstOrDefault(n => !_consumed.Contains(n.Name)) is { Name: not null } unknown)
                {
                    throw new UsageException($"Unknown option {unknown.Name}.");
                }

                if (_positional.Count > _consumed.Count(c => c.StartsWith('#')))
                {
                    throw new UsageException($"Unexpected argument '{_positional[^1]}'.");
                }
            }
        }

        /// <summary>ANSI colors, unless the output is redirected or NO_COLOR is set.</summary>
        private sealed class Style
        {
            private readonly bool _enabled = !Console.IsOutputRedirected && Environment.GetEnvironmentVariable("NO_COLOR") is null;

            public string Bold(string text) => Wrap(text, "1");

            public string Dim(string text) => Wrap(text, "2");

            public string Green(string text) => Wrap(text, "32");

            public string Red(string text) => Wrap(text, "31");

            private string Wrap(string text, string code) => _enabled ? $"\u001b[{code}m{text}\u001b[0m" : text;
        }
    }
}
