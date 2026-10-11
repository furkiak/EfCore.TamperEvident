using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace EfCore.TamperEvident.AspNetCore
{
    /// <summary>
    /// The files of the dashboard, embedded in the assembly.
    /// </summary>
    internal static class DashboardAssets
    {
        private static readonly Dictionary<string, Asset> Cache = new(StringComparer.Ordinal);
        private static readonly object Gate = new();

        public static string Version { get; } =
            typeof(DashboardAssets).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "2.0.0";

        public static Asset? Find(string name)
        {
            lock (Gate)
            {
                if (Cache.TryGetValue(name, out var cached))
                {
                    return cached;
                }

                using var stream = typeof(DashboardAssets).Assembly.GetManifestResourceStream("wwwroot/" + name);
                if (stream is null)
                {
                    return null;
                }

                using var buffer = new MemoryStream();
                stream.CopyTo(buffer);
                var bytes = buffer.ToArray();
                var asset = new Asset(bytes, ContentTypeOf(name), "\"" + Convert.ToHexString(SHA256.HashData(bytes))[..16].ToLowerInvariant() + "\"");
                Cache[name] = asset;
                return asset;
            }
        }

        /// <summary>The page with the base address, title and version filled in.</summary>
        public static string RenderIndex(string baseHref, string title)
        {
            var template = Encoding.UTF8.GetString(Find("index.html")?.Content
                ?? throw new InvalidOperationException("The dashboard page is missing from the assembly."));
            return template
                .Replace("{{BASE}}", System.Net.WebUtility.HtmlEncode(baseHref), StringComparison.Ordinal)
                .Replace("{{TITLE}}", System.Net.WebUtility.HtmlEncode(title), StringComparison.Ordinal)
                .Replace("{{VERSION}}", System.Net.WebUtility.HtmlEncode(Version), StringComparison.Ordinal);
        }

        private static string ContentTypeOf(string name) => Path.GetExtension(name) switch
        {
            ".css" => "text/css; charset=utf-8",
            ".js" => "text/javascript; charset=utf-8",
            ".svg" => "image/svg+xml",
            ".html" => "text/html; charset=utf-8",
            _ => "application/octet-stream"
        };

        internal sealed record Asset(byte[] Content, string ContentType, string ETag);
    }
}
