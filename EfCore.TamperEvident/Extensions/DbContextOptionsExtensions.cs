using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Interceptors;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Extensions
{
    public static class DbContextOptionsExtensions
    {

        public static DbContextOptionsBuilder UseTamperEvidentAudit(
            this DbContextOptionsBuilder builder,
            Action<TamperEvidentOptions> configureOptions)
        {
            var options = new TamperEvidentOptions();
            configureOptions?.Invoke(options);

            builder.AddInterceptors(new TamperEvidentInterceptor(options));

            return builder;
        }
    }
}