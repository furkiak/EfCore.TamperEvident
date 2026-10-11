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

        private static string? DefaultSelector(ClaimsPrincipal user) =>
            user.Identity?.Name
            ?? user.FindFirst("sub")?.Value
            ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    }
}
