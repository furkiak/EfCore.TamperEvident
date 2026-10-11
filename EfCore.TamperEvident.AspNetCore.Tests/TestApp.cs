using System.Security.Claims;
using System.Text.Encodings.Web;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EfCore.TamperEvident.AspNetCore.Tests
{
    public class Person
    {
        public int Id { get; set; }
        public required string Name { get; set; }
        public string? City { get; set; }
    }

    public class Pet
    {
        public int Id { get; set; }
        public required string Name { get; set; }
    }

    public class AppDb : DbContext
    {
        public AppDb(DbContextOptions<AppDb> options) : base(options)
        {
        }

        public DbSet<Person> People => Set<Person>();

        public DbSet<Pet> Pets => Set<Pet>();

        protected override void OnModelCreating(ModelBuilder modelBuilder) => modelBuilder.ApplyTamperEvidentAudit();
    }

    /// <summary>Authenticates a request when it carries an <c>X-Test-User</c> header.</summary>
    public sealed class HeaderAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public const string Scheme = "Test";

        public HeaderAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("X-Test-User", out var user))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, user.ToString()) }, Scheme);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme)));
        }
    }

    /// <summary>A real web host (in memory) with SQLite, the audit trail and the dashboard.</summary>
    public sealed class TestApp : IAsyncDisposable
    {
        public const string Key = "aspnetcore-tests-secret-key-0123456789abcdef";

        private readonly SqliteConnection _connection = new("DataSource=:memory:");
        private WebApplication? _app;

        public HttpClient Client { get; private set; } = null!;

        public IServiceProvider Services => _app!.Services;

        public static async Task<TestApp> StartAsync(
            string environment = "Development",
            Action<DashboardOptions>? configureDashboard = null,
            Func<RouteGroupBuilder, RouteGroupBuilder>? configureGroup = null,
            bool registerAuditOptions = true,
            Action<IServiceCollection>? configureServices = null,
            string pattern = "/audit")
        {
            var app = new TestApp();
            await app.InitializeAsync(environment, configureDashboard, configureGroup, registerAuditOptions, configureServices, pattern);
            return app;
        }

        private async Task InitializeAsync(
            string environment, Action<DashboardOptions>? configureDashboard, Func<RouteGroupBuilder, RouteGroupBuilder>? configureGroup,
            bool registerAuditOptions, Action<IServiceCollection>? configureServices, string pattern)
        {
            _connection.Open();

            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = environment });
            builder.WebHost.UseTestServer();
            builder.Logging.ClearProviders();

            builder.Services.AddHttpContextAccessor();
            builder.Services.AddAuthentication(HeaderAuthHandler.Scheme).AddScheme<AuthenticationSchemeOptions, HeaderAuthHandler>(HeaderAuthHandler.Scheme, _ => { });
            builder.Services.AddAuthorization();

            if (registerAuditOptions)
            {
                builder.Services.AddTamperEvident((sp, o) =>
                {
                    o.HmacSecretKey = Key;
                    o.UseHttpContextUser(sp);
                });
                builder.Services.AddDbContext<AppDb>((sp, o) => o.UseSqlite(_connection).UseTamperEvidentAudit(sp));
            }
            else
            {
                builder.Services.AddDbContext<AppDb>(o => o.UseSqlite(_connection).UseTamperEvidentAudit(a => a.HmacSecretKey = Key));
            }

            configureServices?.Invoke(builder.Services);

            var app = builder.Build();
            app.UseAuthentication();
            app.UseAuthorization();

            var group = app.MapTamperEvidentDashboard<AppDb>(pattern, configureDashboard);
            configureGroup?.Invoke(group);

            await using (var scope = app.Services.CreateAsyncScope())
            {
                await scope.ServiceProvider.GetRequiredService<AppDb>().Database.EnsureCreatedAsync();
            }

            await app.StartAsync();
            _app = app;
            Client = app.GetTestClient();
        }

        public async Task SeedAsync(int people = 3)
        {
            await using var scope = Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDb>();
            for (var i = 1; i <= people; i++)
            {
                using (AuditScope.Begin(i % 2 == 0 ? "bob" : "alice"))
                {
                    db.People.Add(new Person { Name = "person-" + i, City = "Istanbul" });
                    await db.SaveChangesAsync();
                }
            }

            using (AuditScope.Begin("alice"))
            {
                db.Pets.Add(new Pet { Name = "Rex" });
                await db.SaveChangesAsync();
                (await db.People.FirstAsync()).City = "Ankara";
                await db.SaveChangesAsync();
            }
        }

        public async Task ExecuteAsync(string sql, params object[] parameters)
        {
            await using var scope = Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDb>();
            await db.Database.ExecuteSqlRawAsync(sql, parameters);
        }

        public async ValueTask DisposeAsync()
        {
            Client?.Dispose();
            if (_app is not null)
            {
                await _app.DisposeAsync();
            }

            _connection.Dispose();
        }
    }
}
