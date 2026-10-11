using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;

namespace EfCore.TamperEvident.AspNetCore
{
    /// <summary>
    /// Maps the audit dashboard.
    /// </summary>
    public static class TamperEvidentDashboardExtensions
    {
        private const string ContentSecurityPolicy =
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
            "connect-src 'self'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'";

        /// <summary>
        /// Maps the dashboard (a single page plus a JSON API) that lets you browse, filter, verify and export the audit
        /// trail stored by <typeparamref name="TContext"/>. It exposes sensitive data: chain it with
        /// <c>RequireAuthorization(...)</c>. Outside of Development it refuses to serve unless it is protected or
        /// <see cref="DashboardOptions.AllowAnonymous"/> is set.
        /// </summary>
        /// <typeparam name="TContext">The context that stores the audit trail.</typeparam>
        /// <param name="endpoints">The endpoint route builder (usually the <c>WebApplication</c>).</param>
        /// <param name="pattern">The base path of the dashboard. Defaults to <c>/tamper-evident</c>.</param>
        /// <param name="configure">Configures the dashboard.</param>
        /// <returns>The route group, so that conventions such as <c>RequireAuthorization</c> can be added.</returns>
        public static RouteGroupBuilder MapTamperEvidentDashboard<TContext>(
            this IEndpointRouteBuilder endpoints, string pattern = "/tamper-evident", Action<DashboardOptions>? configure = null)
            where TContext : DbContext
        {
            ArgumentNullException.ThrowIfNull(endpoints);

            var options = new DashboardOptions();
            configure?.Invoke(options);

            var prefix = "/" + pattern.Trim('/');
            var group = endpoints.MapGroup(prefix);
            var api = new DashboardApi<TContext>(options);

            group.AddEndpointFilter(async (context, next) =>
            {
                var http = context.HttpContext;
                if (!IsAccessAllowed(http, options))
                {
                    return Results.Problem(
                        statusCode: StatusCodes.Status403Forbidden,
                        title: "The audit dashboard is not protected",
                        detail: "Outside of the Development environment the dashboard requires authorization. " +
                                "Chain RequireAuthorization(...) after MapTamperEvidentDashboard, or set DashboardOptions.AllowAnonymous.");
                }

                var headers = http.Response.Headers;
                headers["X-Content-Type-Options"] = "nosniff";
                headers["Referrer-Policy"] = "no-referrer";
                headers["X-Frame-Options"] = "DENY";
                return await next(context);
            });

            group.MapGet("/", (HttpContext http) =>
            {
                http.Response.Headers["Content-Security-Policy"] = ContentSecurityPolicy;
                http.Response.Headers.CacheControl = "no-store";
                var baseHref = http.Request.PathBase.Value + prefix + "/";
                return Results.Content(DashboardAssets.RenderIndex(baseHref, options.Title), "text/html; charset=utf-8");
            }).ExcludeFromDescription();

            group.MapGet("/assets/{file}", (string file, HttpContext http) =>
            {
                var asset = DashboardAssets.Find(file);
                if (asset is null || file.Contains("index", StringComparison.OrdinalIgnoreCase))
                {
                    return Results.NotFound();
                }

                http.Response.Headers.ETag = asset.ETag;
                http.Response.Headers.CacheControl = "private, max-age=300";
                if (http.Request.Headers.IfNoneMatch == asset.ETag)
                {
                    return Results.StatusCode(StatusCodes.Status304NotModified);
                }

                return Results.Bytes(asset.Content, asset.ContentType);
            }).ExcludeFromDescription();

            var apiGroup = group.MapGroup("/api");
            apiGroup.AddEndpointFilter(async (context, next) =>
            {
                context.HttpContext.Response.Headers.CacheControl = "no-store";
                return await next(context);
            });
            apiGroup.MapGet("/overview", api.Overview).ExcludeFromDescription();
            apiGroup.MapGet("/logs", api.Logs).ExcludeFromDescription();
            apiGroup.MapGet("/activity", DashboardApi<TContext>.Activity).ExcludeFromDescription();
            apiGroup.MapPost("/verify", api.Verify).ExcludeFromDescription();
            apiGroup.MapGet("/export", api.Export).ExcludeFromDescription();

            return group;
        }

        private static bool IsAccessAllowed(HttpContext http, DashboardOptions options)
        {
            if (options.AllowAnonymous)
            {
                return true;
            }

            var metadata = http.GetEndpoint()?.Metadata;
            if (metadata?.GetMetadata<IAuthorizeData>() is not null || metadata?.GetMetadata<IAllowAnonymous>() is not null)
            {
                return true;
            }

            return http.RequestServices.GetService(typeof(IHostEnvironment)) is IHostEnvironment { EnvironmentName: "Development" };
        }
    }
}
