using System.Text.Json;
using EfCore.TamperEvident.Models;

namespace EfCore.TamperEvident.Services
{
    /// <summary>
    /// Appends anchors as JSON lines to a file. The file is only a useful anchor when the database administrators
    /// cannot rewrite it, for example on a different server, a WORM volume or a mounted object-storage bucket.
    /// </summary>
    public class FileAnchorPublisher : IAnchorPublisher
    {
        private static readonly SemaphoreSlim WriteLock = new(1, 1);

        private readonly string _path;

        /// <summary>Creates the publisher.</summary>
        /// <param name="path">The file the anchors are appended to. Missing directories are created.</param>
        public FileAnchorPublisher(string path)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            _path = path;
        }

        /// <inheritdoc />
        public async Task PublishAsync(AuditAnchor anchor, CancellationToken cancellationToken = default)
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(_path));
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var line = JsonSerializer.Serialize(new AnchorLine(
                anchor.TableName, anchor.Hash, anchor.SequenceNumber, anchor.RecordCount, anchor.CreatedUtc.UtcDateTime)) + Environment.NewLine;

            await WriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await File.AppendAllTextAsync(_path, line, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                WriteLock.Release();
            }
        }

        /// <summary>Reads the anchors back from a file written by this publisher.</summary>
        /// <param name="path">The anchor file.</param>
        /// <returns>The anchors in the order they were written.</returns>
        public static IReadOnlyList<AuditAnchor> ReadAnchors(string path)
        {
            var anchors = new List<AuditAnchor>();
            foreach (var line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                var parsed = JsonSerializer.Deserialize<AnchorLine>(line)
                    ?? throw new InvalidDataException($"'{path}' contains an unreadable anchor line.");
                anchors.Add(new AuditAnchor(
                    parsed.TableName, parsed.Hash, parsed.SequenceNumber, parsed.RecordCount,
                    new DateTimeOffset(DateTime.SpecifyKind(parsed.CreatedUtc, DateTimeKind.Utc))));
            }

            return anchors;
        }

        private sealed record AnchorLine(string TableName, string Hash, long SequenceNumber, int RecordCount, DateTime CreatedUtc);
    }
}
