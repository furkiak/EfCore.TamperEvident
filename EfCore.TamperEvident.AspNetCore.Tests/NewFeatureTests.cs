using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace EfCore.TamperEvident.AspNetCore.Tests
{
    /// <summary>Incremental scheduled verification, request metadata and the record history of the dashboard.</summary>
    public class NewFeatureTests
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

        private static async Task AddPeopleAsync(TestApp app, int count)
        {
            await using var scope = app.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDb>();
            for (var i = 0; i < count; i++)
            {
                db.People.Add(new Person { Name = "new-" + i });
            }

            await db.SaveChangesAsync();
        }

        [Fact]
        public async Task ScheduledVerification_IsFullFirst_ThenIncremental()
        {
            await using var app = await StartAsync();
            await app.SeedAsync();
            var service = ServiceOf(app);
            var state = app.Services.GetRequiredService<AuditVerificationState>();

            var first = await service.VerifyOnceAsync(CancellationToken.None);
            Assert.True(first.IsValid, first.Message);
            Assert.All(first.Tables, t => Assert.False(t.IsIncremental));
            Assert.Equal(5, first.RecordsChecked);
            Assert.NotNull(state.LastFullVerificationUtc);
            Assert.Equal(2, state.Checkpoints!.Count);

            await AddPeopleAsync(app, 2);
            var second = await service.VerifyOnceAsync(CancellationToken.None);
            Assert.True(second.IsValid, second.Message);
            Assert.Equal(2, second.RecordsChecked);
            Assert.All(second.Tables, t => Assert.True(t.IsIncremental));

            var health = await app.Services.GetRequiredService<Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckService>().CheckHealthAsync();
            Assert.Equal(true, health.Entries["tamper-evident"].Data["incremental"]);
        }

        [Fact]
        public async Task AFailedIncrementalRun_ForgetsTheCheckpoints()
        {
            await using var app = await StartAsync();
            await app.SeedAsync();
            var service = ServiceOf(app);
            var state = app.Services.GetRequiredService<AuditVerificationState>();
            await service.VerifyOnceAsync(CancellationToken.None);

            await AddPeopleAsync(app, 1);
            await app.ExecuteAsync("UPDATE AuditLogs SET UserId = 'mallory' WHERE TableName = 'People' AND SequenceNumber = 5");
            var failed = await service.VerifyOnceAsync(CancellationToken.None);
            Assert.False(failed.IsValid);
            Assert.Null(state.Checkpoints);

            // The next run starts from the beginning again.
            var next = await service.VerifyOnceAsync(CancellationToken.None);
            Assert.All(next.Tables, t => Assert.False(t.IsIncremental));
        }

        [Fact]
        public async Task FullVerifications_RunOnTheirOwnSchedule()
        {
            await using var app = await StartAsync(o => o.FullVerificationInterval = TimeSpan.FromTicks(1));
            await app.SeedAsync();
            var service = ServiceOf(app);
            await service.VerifyOnceAsync(CancellationToken.None);

            var second = await service.VerifyOnceAsync(CancellationToken.None);
            Assert.All(second.Tables, t => Assert.False(t.IsIncremental));
            Assert.Equal(5, second.RecordsChecked);
        }

        [Fact]
        public async Task IncrementalVerification_CanBeTurnedOff()
        {
            await using var app = await StartAsync(o => o.Incremental = false);
            await app.SeedAsync();
            var service = ServiceOf(app);
            await service.VerifyOnceAsync(CancellationToken.None);
            var second = await service.VerifyOnceAsync(CancellationToken.None);
            Assert.Equal(5, second.RecordsChecked);
        }

        [Fact]
        public void TheFullVerificationInterval_MustBePositive()
        {
            Assert.Throws<ArgumentException>(() => new ServiceCollection()
                .AddTamperEvidentVerification<AppDb>(o => o.FullVerificationInterval = TimeSpan.Zero));
        }

        [Fact]
        public void RequestMetadata_IsTakenFromTheCurrentRequest()
        {
            var services = new ServiceCollection().AddHttpContextAccessor().BuildServiceProvider();
            var http = new DefaultHttpContext();
            http.Connection.RemoteIpAddress = IPAddress.Parse("::ffff:203.0.113.7");
            http.Request.Method = "POST";
            http.Request.PathBase = "/app";
            http.Request.Path = "/orders/42";
            http.Request.QueryString = new QueryString("?token=secret");
            http.Request.Headers.UserAgent = "Mozilla/5.0 " + new string('x', 400);
            http.TraceIdentifier = "trace-1";
            services.GetRequiredService<IHttpContextAccessor>().HttpContext = http;

            var options = new TamperEvidentOptions { MetadataProvider = _ => new Dictionary<string, object?> { ["tenant"] = "acme" } }
                .UseHttpRequestMetadata(services, o => o.RequestId = true);
            var metadata = options.MetadataProvider!(null!)!.ToDictionary(p => p.Key, p => p.Value);

            Assert.Equal("acme", metadata["tenant"]);
            Assert.Equal("203.0.113.7", metadata["ip"]);
            Assert.Equal("POST /app/orders/42", metadata["request"]);
            Assert.Equal(256, ((string)metadata["userAgent"]!).Length);
            Assert.Equal("trace-1", metadata["requestId"]);
            Assert.DoesNotContain("secret", string.Join(",", metadata.Values));
        }

        [Fact]
        public async Task RequestMetadata_EndsUpInTheAuditEntries()
        {
            await using var app = await TestApp.StartAsync(configureServices: services => services.AddTamperEvident((sp, o) =>
            {
                o.HmacSecretKey = TestApp.Key;
                o.UseHttpContextUser(sp).UseHttpRequestMetadata(sp);
            }));
            var accessor = app.Services.GetRequiredService<IHttpContextAccessor>();
            var http = new DefaultHttpContext();
            http.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.4");
            http.Request.Method = "PUT";
            http.Request.Path = "/people";
            accessor.HttpContext = http;

            await using (var scope = app.Services.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDb>();
                db.People.Add(new Person { Name = "Ada" });
                await db.SaveChangesAsync();
            }

            accessor.HttpContext = null;
            await using (var scope = app.Services.CreateAsyncScope())
            {
                var log = await scope.ServiceProvider.GetRequiredService<AppDb>().AuditLogs().SingleAsync();
                Assert.Equal("{\"ip\":\"198.51.100.4\",\"request\":\"PUT /people\"}", log.Metadata);
            }
        }

        [Fact]
        public async Task TheLogsApi_ReturnsMetadata_AndCanListOldestFirst()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();
            await using (var scope = app.Services.CreateAsyncScope())
            using (AuditScope.WithReason("Typo"))
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDb>();
                (await db.People.FirstAsync()).Name = "fixed";
                await db.SaveChangesAsync();
            }

            using var document = JsonDocument.Parse(await app.Client.GetStringAsync("/audit/api/logs?table=People&recordId=1&order=asc"));
            var items = document.RootElement.GetProperty("items").EnumerateArray().ToList();
            Assert.Equal(new long[] { 1, 4, 5 }, items.Select(i => i.GetProperty("sequence").GetInt64()));
            Assert.Equal("{\"reason\":\"Typo\"}", items[^1].GetProperty("metadata").GetString());
            Assert.False(document.RootElement.GetProperty("totalIsEstimate").GetBoolean());
        }

        [Fact]
        public async Task TheOverview_IsBuiltFromTheChainHeads()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();

            using var document = JsonDocument.Parse(await app.Client.GetStringAsync("/audit/api/overview"));
            var tables = document.RootElement.GetProperty("tables").EnumerateArray().ToList();
            Assert.Equal(new[] { "People", "Pets" }, tables.Select(t => t.GetProperty("table").GetString()));
            Assert.Equal(4, tables[0].GetProperty("records").GetInt64());
            Assert.Equal(5, document.RootElement.GetProperty("totals").GetProperty("records").GetInt64());
            Assert.Equal(2, document.RootElement.GetProperty("totals").GetProperty("users").GetInt32());
            Assert.Equal(30, document.RootElement.GetProperty("totals").GetProperty("userDays").GetInt32());
        }

        [Fact]
        public async Task AFullVerificationFromTheDashboard_SeedsTheCheckpoints()
        {
            await using var app = await StartAsync();
            await app.SeedAsync();

            using var request = new HttpRequestMessage(HttpMethod.Post, "/audit/api/verify") { Content = JsonContent.Create(new { }) };
            request.Headers.Add("X-Requested-With", "tamper-evident");
            using var response = await app.Client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            using var report = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.False(report.RootElement.GetProperty("incremental").GetBoolean());

            await AddPeopleAsync(app, 1);
            var next = await ServiceOf(app).VerifyOnceAsync(CancellationToken.None);
            Assert.Equal(1, next.RecordsChecked);
        }

        [Fact]
        public async Task RedactedEntries_AreReportedByTheDashboard()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();
            await using (var scope = app.Services.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDb>();
                await db.RedactAuditTrailAsync("People", "1", new AuditRedactionRequest { Reason = "GDPR", Properties = new[] { "Name" } });
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, "/audit/api/verify") { Content = JsonContent.Create(new { table = "People" }) };
            request.Headers.Add("X-Requested-With", "tamper-evident");
            using var response = await app.Client.SendAsync(request);
            using var report = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var people = report.RootElement.GetProperty("tables")[0];
            Assert.True(people.GetProperty("isValid").GetBoolean());
            Assert.Equal(1, people.GetProperty("redactedRecords").GetInt64()); // the later update only changed the city

            using var activity = JsonDocument.Parse(await app.Client.GetStringAsync("/audit/api/activity?days=1"));
            Assert.Equal(1, activity.RootElement.GetProperty("series")[0].GetProperty("redacted").GetInt32());
        }
    }
}
