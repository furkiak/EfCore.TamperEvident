using EfCore.TamperEvident.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace EfCore.TamperEvident.AspNetCore
{
    /// <summary>
    /// Registration of the scheduled verification and its health check.
    /// </summary>
    public static class VerificationServiceCollectionExtensions
    {
        /// <summary>
        /// Verifies the audit trail of <typeparamref name="TContext"/> on a schedule (hourly by default). Requires
        /// <see cref="ServiceCollectionExtensions.AddTamperEvident(IServiceCollection, Action{Configuration.TamperEvidentOptions})"/>.
        /// </summary>
        /// <typeparam name="TContext">The context that stores the audit trail.</typeparam>
        /// <param name="services">The service collection.</param>
        /// <param name="configure">Configures the schedule and what happens when tampering is found.</param>
        /// <returns>The same collection, for chaining.</returns>
        public static IServiceCollection AddTamperEvidentVerification<TContext>(
            this IServiceCollection services, Action<TamperEvidentVerificationOptions>? configure = null)
            where TContext : DbContext
        {
            ArgumentNullException.ThrowIfNull(services);

            var options = new TamperEvidentVerificationOptions();
            configure?.Invoke(options);
            if (options.Interval <= TimeSpan.Zero)
            {
                throw new ArgumentException("The verification interval must be positive.", nameof(configure));
            }

            services.Replace(ServiceDescriptor.Singleton(options));
            services.TryAddSingleton<AuditVerificationState>();
            services.AddTamperEvidentVerifier<TContext>();
            services.AddHostedService<TamperEvidentVerificationService<TContext>>();
            return services;
        }

        /// <summary>
        /// Adds a health check that reflects the latest verification. Requires <c>AddTamperEvidentVerification</c>.
        /// </summary>
        /// <param name="builder">The health checks builder.</param>
        /// <param name="name">The name of the check.</param>
        /// <param name="failureStatus">The status reported when tampering was detected. Defaults to unhealthy.</param>
        /// <param name="tags">Optional tags.</param>
        /// <returns>The same builder, for chaining.</returns>
        public static IHealthChecksBuilder AddTamperEvidentHealthCheck(
            this IHealthChecksBuilder builder,
            string name = "tamper-evident",
            HealthStatus? failureStatus = null,
            IEnumerable<string>? tags = null)
        {
            ArgumentNullException.ThrowIfNull(builder);
            return builder.AddCheck<TamperEvidentHealthCheck>(name, failureStatus, tags ?? Array.Empty<string>());
        }
    }
}
