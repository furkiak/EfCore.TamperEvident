using System.Text.RegularExpressions;
using EfCore.TamperEvident.Services;

namespace EfCore.TamperEvident.AspNetCore
{
    /// <summary>
    /// Where the externally stored anchors come from.
    /// </summary>
    public static partial class AnchorSources
    {
        [GeneratedRegex("(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")]
        private static partial Regex HashPattern();

        /// <summary>
        /// Reads the anchors that a <see cref="FileAnchorPublisher"/> wrote. The file is read on every call.
        /// Use the result as <see cref="TamperEvidentVerificationOptions.AnchorProvider"/>.
        /// </summary>
        /// <param name="path">The anchor file.</param>
        public static Func<IServiceProvider, CancellationToken, Task<IReadOnlyDictionary<string, IEnumerable<string>>?>> FromFile(string path)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);

            return (_, _) =>
            {
                if (!File.Exists(path))
                {
                    return Task.FromResult<IReadOnlyDictionary<string, IEnumerable<string>>?>(null);
                }

                IReadOnlyDictionary<string, IEnumerable<string>> grouped = FileAnchorPublisher.ReadAnchors(path)
                    .GroupBy(a => a.TableName, StringComparer.Ordinal)
                    .ToDictionary(g => g.Key, g => (IEnumerable<string>)g.Select(a => a.Hash).ToList(), StringComparer.Ordinal);
                return Task.FromResult<IReadOnlyDictionary<string, IEnumerable<string>>?>(grouped);
            };
        }

        /// <summary>
        /// Pulls every 64 character hex string out of a text, for example the pasted bodies of anchor e-mails.
        /// </summary>
        /// <param name="text">Any text.</param>
        /// <returns>The distinct hashes in lower case.</returns>
        public static IReadOnlyList<string> ExtractHashes(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return Array.Empty<string>();
            }

            return HashPattern().Matches(text).Select(m => m.Value.ToLowerInvariant()).Distinct().ToList();
        }
    }
}
