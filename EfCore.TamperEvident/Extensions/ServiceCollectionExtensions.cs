using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Interceptors;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace EfCore.TamperEvident.Extensions
{
    /// <summary>
    /// Dependency injection support.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registers <see cref="TamperEvidentOptions"/> and one shared <see cref="TamperEvidentInterceptor"/> as singletons.
        /// Enable the interceptor on your context with
        /// <see cref="DbContextOptionsExtensions.UseTamperEvidentAudit(DbContextOptionsBuilder, IServiceProvider)"/>.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="configure">Configures the audit trail.</param>
        /// <returns>The same collection, for chaining.</returns>
        public static IServiceCollection AddTamperEvident(this IServiceCollection services, Action<TamperEvidentOptions> configure)
        {
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(configure);

            var options = new TamperEvidentOptions();
            configure(options);
            options.Validate();

            services.Replace(ServiceDescriptor.Singleton(options));
            services.TryAddSingleton(sp => new TamperEvidentInterceptor(sp.GetRequiredService<TamperEvidentOptions>()));
            return services;
        }

        /// <summary>
        /// Registers a scoped <see cref="AuditVerifier"/> that verifies the audit trail stored by <typeparamref name="TContext"/>.
        /// Requires <see cref="AddTamperEvident"/>.
        /// </summary>
        /// <typeparam name="TContext">The context that stores the audit trail.</typeparam>
        /// <param name="services">The service collection.</param>
        /// <returns>The same collection, for chaining.</returns>
        public static IServiceCollection AddTamperEvidentVerifier<TContext>(this IServiceCollection services)
            where TContext : DbContext
        {
            ArgumentNullException.ThrowIfNull(services);

            services.TryAddScoped(sp => new AuditVerifier(
                sp.GetRequiredService<TContext>(),
                sp.GetRequiredService<TamperEvidentOptions>()));
            return services;
        }
    }
}
