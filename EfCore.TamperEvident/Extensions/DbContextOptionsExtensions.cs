using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Interceptors;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.TamperEvident.Extensions
{
    /// <summary>
    /// Registers the tamper-evident audit trail on a <see cref="DbContextOptionsBuilder"/>.
    /// </summary>
    public static class DbContextOptionsExtensions
    {
        /// <summary>
        /// Enables the tamper-evident audit trail.
        /// </summary>
        /// <param name="builder">The options builder of the context.</param>
        /// <param name="configureOptions">Configures the audit trail.</param>
        /// <returns>The same builder, for chaining.</returns>
        /// <exception cref="InvalidOperationException">The configuration is not valid, for example no secret key was set.</exception>
        public static DbContextOptionsBuilder UseTamperEvidentAudit(
            this DbContextOptionsBuilder builder,
            Action<TamperEvidentOptions> configureOptions)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(configureOptions);

            var options = new TamperEvidentOptions();
            configureOptions(options);
            return builder.UseTamperEvidentAudit(options);
        }

        /// <summary>
        /// Enables the tamper-evident audit trail with options that are created elsewhere.
        /// </summary>
        /// <param name="builder">The options builder of the context.</param>
        /// <param name="options">The configuration.</param>
        /// <returns>The same builder, for chaining.</returns>
        public static DbContextOptionsBuilder UseTamperEvidentAudit(
            this DbContextOptionsBuilder builder,
            TamperEvidentOptions options)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(options);

            return builder.AddInterceptors(new TamperEvidentInterceptor(options));
        }

        /// <summary>
        /// Enables the tamper-evident audit trail using the registration made with
        /// <see cref="ServiceCollectionExtensions.AddTamperEvident(IServiceCollection, Action{TamperEvidentOptions})"/>.
        /// </summary>
        /// <param name="builder">The options builder of the context.</param>
        /// <param name="serviceProvider">The application service provider.</param>
        /// <returns>The same builder, for chaining.</returns>
        public static DbContextOptionsBuilder UseTamperEvidentAudit(
            this DbContextOptionsBuilder builder,
            IServiceProvider serviceProvider)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(serviceProvider);

            return builder.AddInterceptors(serviceProvider.GetRequiredService<TamperEvidentInterceptor>());
        }

        /// <inheritdoc cref="UseTamperEvidentAudit(DbContextOptionsBuilder, Action{TamperEvidentOptions})"/>
        /// <typeparam name="TContext">The context type, kept so that <c>.Options</c> stays strongly typed.</typeparam>
        public static DbContextOptionsBuilder<TContext> UseTamperEvidentAudit<TContext>(
            this DbContextOptionsBuilder<TContext> builder,
            Action<TamperEvidentOptions> configureOptions)
            where TContext : DbContext
        {
            ((DbContextOptionsBuilder)builder).UseTamperEvidentAudit(configureOptions);
            return builder;
        }

        /// <inheritdoc cref="UseTamperEvidentAudit(DbContextOptionsBuilder, TamperEvidentOptions)"/>
        /// <typeparam name="TContext">The context type, kept so that <c>.Options</c> stays strongly typed.</typeparam>
        public static DbContextOptionsBuilder<TContext> UseTamperEvidentAudit<TContext>(
            this DbContextOptionsBuilder<TContext> builder,
            TamperEvidentOptions options)
            where TContext : DbContext
        {
            ((DbContextOptionsBuilder)builder).UseTamperEvidentAudit(options);
            return builder;
        }

        /// <inheritdoc cref="UseTamperEvidentAudit(DbContextOptionsBuilder, IServiceProvider)"/>
        /// <typeparam name="TContext">The context type, kept so that <c>.Options</c> stays strongly typed.</typeparam>
        public static DbContextOptionsBuilder<TContext> UseTamperEvidentAudit<TContext>(
            this DbContextOptionsBuilder<TContext> builder,
            IServiceProvider serviceProvider)
            where TContext : DbContext
        {
            ((DbContextOptionsBuilder)builder).UseTamperEvidentAudit(serviceProvider);
            return builder;
        }
    }
}
