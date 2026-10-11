using System.Security.Claims;
using EfCore.TamperEvident.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.TamperEvident.AspNetCore
{
    /// <summary>
    /// Attributes audited changes to the user of the current HTTP request.
    /// </summary>
    public static class HttpContextUser
    {
        /// <summary>
        /// Uses the authenticated user of the current request as the audit user. Outside of a request the default
        /// user (<c>System</c>) is used, for unauthenticated requests <c>anonymous</c>. Requires
        /// <c>services.AddHttpContextAccessor()</c> and the <c>AddTamperEvident((sp, options) =&gt; ...)</c> overload.
        /// </summary>
        /// <param name="options">The options to configure.</param>
        /// <param name="serviceProvider">The application services.</param>
        /// <param name="selector">
        /// Picks the user id from the principal. By default the name, then the <c>sub</c> / name identifier claim.
        /// </param>
        /// <returns>The same options, for chaining.</returns>
        public static TamperEvidentOptions UseHttpContextUser(
            this TamperEvidentOptions options, IServiceProvider serviceProvider, Func<ClaimsPrincipal, string?>? selector = null)
        {
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(serviceProvider);

            var accessor = serviceProvider.GetService<IHttpContextAccessor>()
                ?? throw new InvalidOperationException("IHttpContextAccessor is not registered. Call services.AddHttpContextAccessor().");
            selector ??= DefaultSelector;

            options.UserIdProvider = _ =>
            {
                var http = accessor.HttpContext;
                if (http is null)
                {
                    return null;
                }

                return http.User.Identity?.IsAuthenticated == true ? selector(http.User) : "anonymous";
            };
            return options;
        }

        /// <summary>
        /// Records where a change came from, as metadata of every audit entry written during an HTTP request: the client
        /// IP address, the user agent and the request (method and path, never the query string). Configure the forwarded
        /// headers middleware when the application runs behind a proxy, so that the real client address is seen. The
        /// values are personal data in many jurisdictions: they can be redacted later like any other metadata.
        /// Requires <c>services.AddHttpContextAccessor()</c>; an existing <see cref="TamperEvidentOptions.MetadataProvider"/>
        /// is kept and combined.
        /// </summary>
        /// <param name="options">The options to configure.</param>
        /// <param name="serviceProvider">The application services.</param>
        /// <param name="configure">Chooses what is recorded.</param>
        /// <returns>The same options, for chaining.</returns>
        public static TamperEvidentOptions UseHttpRequestMetadata(
            this TamperEvidentOptions options, IServiceProvider serviceProvider, Action<HttpRequestMetadataOptions>? configure = null)
        {
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(serviceProvider);

            var accessor = serviceProvider.GetService<IHttpContextAccessor>()
                ?? throw new InvalidOperationException("IHttpContextAccessor is not registered. Call services.AddHttpContextAccessor().");
            var settings = new HttpRequestMetadataOptions();
            configure?.Invoke(settings);

            var previous = options.MetadataProvider;
            options.MetadataProvider = context =>
            {
                var values = new Dictionary<string, object?>(StringComparer.Ordinal);
                if (previous?.Invoke(context) is { } earlier)
                {
                    foreach (var (key, value) in earlier)
                    {
                        values[key] = value;
                    }
                }

                if (accessor.HttpContext is { } http)
                {
                    if (settings.IpAddress && http.Connection.RemoteIpAddress is { } ip)
                    {
                        values["ip"] = (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
                    }

                    if (settings.UserAgent && http.Request.Headers.UserAgent.ToString() is { Length: > 0 } agent)
                    {
                        values["userAgent"] = agent.Length > 256 ? agent[..256] : agent;
                    }

                    if (settings.Request)
                    {
                        values["request"] = http.Request.Method + " " + http.Request.PathBase + http.Request.Path;
                    }

                    if (settings.RequestId)
                    {
                        values["requestId"] = http.TraceIdentifier;
                    }
                }

                return values;
            };
            return options;
        }

        private static string? DefaultSelector(ClaimsPrincipal user) =>
            user.Identity?.Name
            ?? user.FindFirst("sub")?.Value
            ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    }

    /// <summary>
    /// What <see cref="HttpContextUser.UseHttpRequestMetadata"/> records.
    /// </summary>
    public sealed class HttpRequestMetadataOptions
    {
        /// <summary>The client IP address, as <c>ip</c>. Defaults to <c>true</c>.</summary>
        public bool IpAddress { get; set; } = true;

        /// <summary>The <c>User-Agent</c> header (at most 256 characters), as <c>userAgent</c>. Defaults to <c>true</c>.</summary>
        public bool UserAgent { get; set; } = true;

        /// <summary>The method and path of the request (without the query string), as <c>request</c>. Defaults to <c>true</c>.</summary>
        public bool Request { get; set; } = true;

        /// <summary>The ASP.NET Core request id (<c>HttpContext.TraceIdentifier</c>), as <c>requestId</c>. Defaults to <c>false</c>.</summary>
        public bool RequestId { get; set; }
    }
}
