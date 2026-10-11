using EfCore.TamperEvident.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using System.Security.Claims;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.AspNetCore.Tests
{
    public class VerificationTests
    {
        private static Task<TestApp> StartAsync(Action<TamperEvidentVerificationOptions>? configure = null) =>
            TestApp.StartAsync(configureServices: services =>
            {
                services.AddTamperEvidentVerification<AppDb>(o =>
                {
                    o.InitialDelay = TimeSpan.FromHours(1);
                    configure?.Invoke(o);
                });
                services.AddHealthChecks().AddTamperEvidentHealthCheck();
            });

        private static TamperEvidentVerificationService<AppDb> ServiceOf(TestApp app) =>
            app.Services.GetServices<IHostedService>().OfType<TamperEvidentVerificationService<AppDb>>().Single();

        [Fact]
        public async Task OneVerification_StoresItsResult()
        {
            await using var app = await StartAsync();
            await app.SeedAsync();

            var report = await ServiceOf(app).VerifyOnceAsync(CancellationToken.None);

            Assert.True(report.IsValid, report.Message);
            var latest = app.Services.GetRequiredService<AuditVerificationState>().Latest;
            Assert.NotNull(latest);
            Assert.Equal("background", latest!.Source);
            Assert.Equal(5, latest.Report.RecordsChecked);
        }

        [Fact]
        public async Task Tampering_IsReported_ThroughTheCallback_AndTheHealthCheck()
        {
            AuditVerificationReport? alarm = null;
            await using var app = await StartAsync(o => o.OnTamperDetected = (report, _, _) =>
            {
                alarm = report;
                return Task.CompletedTask;
            });
            await app.SeedAsync();
            await app.ExecuteAsync("DELETE FROM AuditLogs WHERE TableName = 'People' AND SequenceNumber = 4");

            var report = await ServiceOf(app).VerifyOnceAsync(CancellationToken.None);

            Assert.False(report.IsValid);
            Assert.Same(report, alarm);

            var health = await app.Services.GetRequiredService<HealthCheckService>().CheckHealthAsync();
            Assert.Equal(HealthStatus.Unhealthy, health.Status);
            var entry = health.Entries["tamper-evident"];
            Assert.Contains("People", (string)entry.Data["failedTables"]);
        }

        [Fact]
        public async Task AFailingCallback_DoesNotBreakTheVerification()
        {
            await using var app = await StartAsync(o => o.OnTamperDetected = (_, _, _) => throw new InvalidOperationException("pager is down"));
            await app.SeedAsync();
            await app.ExecuteAsync("UPDATE AuditLogs SET UserId = 'x' WHERE SequenceNumber = 1");

            var report = await ServiceOf(app).VerifyOnceAsync(CancellationToken.None);

            Assert.False(report.IsValid);
            Assert.False(app.Services.GetRequiredService<AuditVerificationState>().Latest!.Report.IsValid);
        }

        [Fact]
        public async Task StoredAnchors_AreCheckedOnEverySchedule()
        {
            await using var app = await StartAsync(o => o.AnchorProvider = (_, _) =>
                Task.FromResult<IReadOnlyDictionary<string, IEnumerable<string>>?>(new Dictionary<string, IEnumerable<string>>
                {
                    ["People"] = new[] { new string('c', 64) }
                }));
            await app.SeedAsync();

            var report = await ServiceOf(app).VerifyOnceAsync(CancellationToken.None);

            Assert.False(report.IsValid);
            Assert.Equal(AuditFailureKind.AnchorMismatch, report.Failures.Single().Failure);
        }

        [Fact]
        public async Task HealthCheck_IsDegraded_UntilTheFirstVerification_ThenHealthy()
        {
            await using var app = await StartAsync();
            await app.SeedAsync();
            var health = app.Services.GetRequiredService<HealthCheckService>();

            Assert.Equal(HealthStatus.Degraded, (await health.CheckHealthAsync()).Status);

            await ServiceOf(app).VerifyOnceAsync(CancellationToken.None);
            var result = await health.CheckHealthAsync();

            Assert.Equal(HealthStatus.Healthy, result.Status);
            Assert.Equal(5L, result.Entries["tamper-evident"].Data["records"]);
        }

        [Fact]
        public async Task HealthCheck_TurnsDegraded_WhenTheLastVerificationIsStale()
        {
            await using var app = await StartAsync(o => o.Interval = TimeSpan.FromMinutes(1));
            var state = app.Services.GetRequiredService<AuditVerificationState>();
            state.Update(new AuditVerificationReport
            {
                IsValid = true,
                Message = "ok",
                CompletedUtc = DateTimeOffset.UtcNow.AddHours(-2)
            }, "background");

            var result = await app.Services.GetRequiredService<HealthCheckService>().CheckHealthAsync();

            Assert.Equal(HealthStatus.Degraded, result.Status);
        }

        [Fact]
        public void TheInterval_MustBePositive()
        {
            Assert.Throws<ArgumentException>(() => new ServiceCollection().AddTamperEvidentVerification<AppDb>(o => o.Interval = TimeSpan.Zero));
        }

        [Fact]
        public async Task TheHostedService_RunsOnItsOwn_AfterTheInitialDelay()
        {
            await using var app = await TestApp.StartAsync(configureServices: services =>
                services.AddTamperEvidentVerification<AppDb>(o =>
                {
                    o.InitialDelay = TimeSpan.Zero;
                    o.Interval = TimeSpan.FromMinutes(5);
                }));

            var state = app.Services.GetRequiredService<AuditVerificationState>();
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (state.Latest is null && DateTime.UtcNow < deadline)
            {
                await Task.Delay(50);
            }

            Assert.NotNull(state.Latest);
            Assert.Equal("background", state.Latest!.Source);
        }

        // ---- HTTP user ---------------------------------------------------------------------------------------------

        [Fact]
        public async Task AuditedChanges_AreAttributedToTheHttpUser()
        {
            await using var app = await TestApp.StartAsync();
            var accessor = app.Services.GetRequiredService<IHttpContextAccessor>();

            async Task SaveAs(HttpContext? context, string name)
            {
                accessor.HttpContext = context;
                await using var scope = app.Services.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<AppDb>();
                db.People.Add(new Person { Name = name });
                await db.SaveChangesAsync();
            }

            var signedIn = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "furkan") }, "Test"))
            };
            await SaveAs(signedIn, "by a user");
            await SaveAs(new DefaultHttpContext(), "by a visitor");
            await SaveAs(null, "by a job");

            await using var scope = app.Services.CreateAsyncScope();
            var users = await scope.ServiceProvider.GetRequiredService<AppDb>().AuditLogs().OrderBy(l => l.SequenceNumber).Select(l => l.UserId).ToListAsync();
            Assert.Equal(new[] { "furkan", "anonymous", "System" }, users);
        }

        [Fact]
        public void TheUserSelector_CanBeCustomised()
        {
            var services = new ServiceCollection().AddHttpContextAccessor().BuildServiceProvider();
            var accessor = services.GetRequiredService<IHttpContextAccessor>();
            accessor.HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("email", "ada@example.com") }, "Test"))
            };

            var options = new TamperEvidentOptions().UseHttpContextUser(services, p => p.FindFirst("email")?.Value);

            Assert.Equal("ada@example.com", options.UserIdProvider!(null!));
        }

        [Fact]
        public void WithoutTheHttpContextAccessor_AHelpfulErrorIsThrown()
        {
            var services = new ServiceCollection().BuildServiceProvider();
            var ex = Assert.Throws<InvalidOperationException>(() => new TamperEvidentOptions().UseHttpContextUser(services));
            Assert.Contains("AddHttpContextAccessor", ex.Message);
        }

        // ---- anchors -----------------------------------------------------------------------------------------------

        [Fact]
        public void ExtractHashes_FindsHashesInWholeMessages()
        {
            var a = new string('a', 64);
            var b = new string('B', 64);
            var text = $"Hello,\nAnchor Hash Key:\n{a}\n\nand later {b}, again {a}. Not a hash: {new string('c', 63)} {new string('d', 65)}";

            var hashes = AnchorSources.ExtractHashes(text);

            Assert.Equal(new[] { a, b.ToLowerInvariant() }, hashes);
            Assert.Empty(AnchorSources.ExtractHashes(null));
            Assert.Empty(AnchorSources.ExtractHashes("   "));
        }

        [Fact]
        public async Task FromFile_ReadsTheAnchorsOfAFilePublisher()
        {
            var path = Path.Combine(Path.GetTempPath(), "te-anchor-source-" + Guid.NewGuid().ToString("N") + ".jsonl");
            try
            {
                var provider = AnchorSources.FromFile(path);
                Assert.Null(await provider(null!, CancellationToken.None));

                var publisher = new FileAnchorPublisher(path);
                await publisher.PublishAsync(new AuditAnchor("People", new string('a', 64), 1, 1, DateTimeOffset.UtcNow));
                await publisher.PublishAsync(new AuditAnchor("People", new string('b', 64), 2, 1, DateTimeOffset.UtcNow));
                await publisher.PublishAsync(new AuditAnchor("Pets", new string('c', 64), 1, 1, DateTimeOffset.UtcNow));

                var anchors = await provider(null!, CancellationToken.None);

                Assert.Equal(2, anchors!["People"].Count());
                Assert.Single(anchors["Pets"]);
            }
            finally
            {
                File.Delete(path);
            }
        }
    }
}
