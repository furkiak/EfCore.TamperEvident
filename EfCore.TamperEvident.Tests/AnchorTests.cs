using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Tests
{
    public class AnchorTests
    {
        private sealed class RecordingPublisher : IAnchorPublisher
        {
            private readonly int _failFirst;
            private int _attempts;

            public RecordingPublisher(int failFirst = 0) => _failFirst = failFirst;

            public ConcurrentQueue<AuditAnchor> Published { get; } = new();

            public int Attempts => _attempts;

            public Task PublishAsync(AuditAnchor anchor, CancellationToken cancellationToken = default)
            {
                if (Interlocked.Increment(ref _attempts) <= _failFirst)
                {
                    throw new IOException("the mail server is down");
                }

                Published.Enqueue(anchor);
                return Task.CompletedTask;
            }
        }

        /// <summary>An implementation written against the 1.x interface that only knows <c>SendAnchorAsync</c>.</summary>
        private sealed class LegacyPublisher : IAnchorPublisher
        {
            public ConcurrentQueue<(string Table, string Hash, int Count)> Sent { get; } = new();

            public Task SendAnchorAsync(string tableName, string currentHash, int recordCount)
            {
                Sent.Enqueue((tableName, currentHash, recordCount));
                return Task.CompletedTask;
            }
        }

        private static Harness HarnessWith(IAnchorPublisher publisher, int threshold = 3, bool awaitDelivery = true) =>
            new(o =>
            {
                o.CustomAnchorPublisher = publisher;
                o.AnchorThreshold = threshold;
                o.AwaitAnchorDelivery = awaitDelivery;
                o.AnchorRetryDelay = TimeSpan.Zero;
            });

        private static async Task AddCustomersAsync(Harness harness, int count, bool oneSavePerCustomer = true)
        {
            await using var db = harness.CreateContext();
            for (var i = 1; i <= count; i++)
            {
                db.Customers.Add(new Customer { Name = $"c{i}" });
                if (oneSavePerCustomer)
                {
                    await db.SaveChangesAsync();
                }
            }

            if (!oneSavePerCustomer)
            {
                await db.SaveChangesAsync();
            }
        }

        [Fact]
        public async Task AnchorIsPublished_EveryTimeTheThresholdIsReached()
        {
            var publisher = new RecordingPublisher();
            using var harness = HarnessWith(publisher, threshold: 3);

            await AddCustomersAsync(harness, 7);

            var anchors = publisher.Published.ToList();
            Assert.Equal(2, anchors.Count);
            Assert.Equal(new long[] { 3, 6 }, anchors.Select(a => a.SequenceNumber));
            Assert.All(anchors, a => Assert.Equal(3, a.RecordCount));
            Assert.All(anchors, a => Assert.Equal("Customers", a.TableName));

            await using var db = harness.CreateContext();
            var hashes = await db.AuditLogs.OrderBy(l => l.SequenceNumber).Select(l => l.CurrentHash).ToListAsync();
            Assert.Equal(hashes[2], anchors[0].Hash);
            Assert.Equal(hashes[5], anchors[1].Hash);

            // 7 entries, 6 of them anchored: one is left unanchored.
            Assert.Equal(1, (await db.AuditChainStates.SingleAsync()).UnanchoredCount);
        }

        [Fact]
        public async Task SeveralAnchorsInOneBatch_AreAllPublished_WithTheHashAtTheirPosition()
        {
            // Regression: the anchor used to carry the newest hash and a count that had already been reset to zero.
            var publisher = new RecordingPublisher();
            using var harness = HarnessWith(publisher, threshold: 3);

            await AddCustomersAsync(harness, 7, oneSavePerCustomer: false);

            var anchors = publisher.Published.ToList();
            Assert.Equal(new long[] { 3, 6 }, anchors.Select(a => a.SequenceNumber));
            Assert.All(anchors, a => Assert.Equal(3, a.RecordCount));

            await using var db = harness.CreateContext();
            var hashes = await db.AuditLogs.OrderBy(l => l.SequenceNumber).Select(l => l.CurrentHash).ToListAsync();
            Assert.Equal(new[] { hashes[2], hashes[5] }, anchors.Select(a => a.Hash));
        }

        [Fact]
        public async Task PublishedAnchors_VerifyAgainstTheChain()
        {
            var publisher = new RecordingPublisher();
            using var harness = HarnessWith(publisher, threshold: 2);
            await AddCustomersAsync(harness, 6);

            await using var db = harness.CreateContext();
            var result = await harness.CreateVerifier(db)
                .VerifyTableIntegrityAsync("Customers", publisher.Published.Select(a => a.Hash));

            Assert.True(result.IsValid, result.Message);
            Assert.Equal(3, result.AnchorsMatched);
        }

        [Fact]
        public async Task NonPositiveThreshold_DisablesAnchoring()
        {
            var publisher = new RecordingPublisher();
            using var harness = HarnessWith(publisher, threshold: 0);

            await AddCustomersAsync(harness, 5);

            Assert.Empty(publisher.Published);
        }

        [Fact]
        public async Task Anchors_AreHeldBackUntilTheCallersTransactionCommits()
        {
            var publisher = new RecordingPublisher();
            using var harness = HarnessWith(publisher, threshold: 2);

            await using var db = harness.CreateContext();
            await using var transaction = await db.Database.BeginTransactionAsync();
            db.Customers.AddRange(new Customer { Name = "a" }, new Customer { Name = "b" });
            await db.SaveChangesAsync();

            Assert.Empty(publisher.Published);

            await transaction.CommitAsync();
            Assert.Single(publisher.Published);
        }

        [Fact]
        public async Task Anchors_AreDiscardedWhenTheCallersTransactionRollsBack()
        {
            var publisher = new RecordingPublisher();
            using var harness = HarnessWith(publisher, threshold: 2);

            await using (var db = harness.CreateContext())
            {
                await using var transaction = await db.Database.BeginTransactionAsync();
                db.Customers.AddRange(new Customer { Name = "a" }, new Customer { Name = "b" });
                await db.SaveChangesAsync();
                await transaction.RollbackAsync();
            }

            // A later, unrelated commit on the same context must not release the discarded anchor either.
            Assert.Empty(publisher.Published);
            await using var verify = harness.CreateContext();
            Assert.Empty(await verify.AuditLogs.ToListAsync());
        }

        [Fact]
        public async Task Anchors_AreReleasedWhenAnAmbientTransactionScopeCommits()
        {
            // SQLite does not enlist in ambient transactions, which EF reports as a warning that is silenced here.
            // What is verified is the interceptor's own hook on the scope: held back until it completed.
            var publisher = new RecordingPublisher();
            var options = new TamperEvidentOptions
            {
                HmacSecretKey = Harness.SecretKey,
                CustomAnchorPublisher = publisher,
                AnchorThreshold = 2,
                AnchorRetryDelay = TimeSpan.Zero
            };

            using var connection = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
            connection.Open();
            var dbOptions = new DbContextOptionsBuilder<TestDbContext>()
                .UseSqlite(connection)
                .ConfigureWarnings(w => w.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.RelationalEventId.AmbientTransactionWarning))
                .UseTamperEvidentAudit(options)
                .Options;
            await using (var setup = new TestDbContext(dbOptions))
            {
                await setup.Database.EnsureCreatedAsync();
            }

            using (var scope = new System.Transactions.TransactionScope(System.Transactions.TransactionScopeAsyncFlowOption.Enabled))
            {
                await using var db = new TestDbContext(dbOptions);
                db.Customers.AddRange(new Customer { Name = "a" }, new Customer { Name = "b" });
                await db.SaveChangesAsync();
                Assert.Empty(publisher.Published);
                scope.Complete();
            }

            await WaitForAsync(() => !publisher.Published.IsEmpty);
            Assert.Single(publisher.Published);
        }

        [Fact]
        public async Task Anchors_AreDroppedWhenAnAmbientTransactionScopeIsNotCompleted()
        {
            var publisher = new RecordingPublisher();
            var options = new TamperEvidentOptions
            {
                HmacSecretKey = Harness.SecretKey,
                CustomAnchorPublisher = publisher,
                AnchorThreshold = 2,
                AnchorRetryDelay = TimeSpan.Zero
            };

            using var connection = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
            connection.Open();
            var dbOptions = new DbContextOptionsBuilder<TestDbContext>()
                .UseSqlite(connection)
                .ConfigureWarnings(w => w.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.RelationalEventId.AmbientTransactionWarning))
                .UseTamperEvidentAudit(options)
                .Options;
            await using (var setup = new TestDbContext(dbOptions))
            {
                await setup.Database.EnsureCreatedAsync();
            }

            using (new System.Transactions.TransactionScope(System.Transactions.TransactionScopeAsyncFlowOption.Enabled))
            {
                await using var db = new TestDbContext(dbOptions);
                db.Customers.AddRange(new Customer { Name = "a" }, new Customer { Name = "b" });
                await db.SaveChangesAsync();
            }

            await Task.Delay(200);
            Assert.Empty(publisher.Published);
        }

        [Fact]
        public async Task FailingDelivery_IsRetried_AndNeverBreaksSaveChanges()
        {
            var publisher = new RecordingPublisher(failFirst: 2);
            using var harness = HarnessWith(publisher, threshold: 1);

            await AddCustomersAsync(harness, 1);

            Assert.Equal(3, publisher.Attempts);
            Assert.Single(publisher.Published);
        }

        [Fact]
        public async Task DeliveryThatKeepsFailing_GivesUpAfterTheConfiguredAttempts()
        {
            var publisher = new RecordingPublisher(failFirst: int.MaxValue);
            using var harness = new Harness(o =>
            {
                o.CustomAnchorPublisher = publisher;
                o.AnchorThreshold = 1;
                o.AnchorMaxAttempts = 4;
                o.AnchorRetryDelay = TimeSpan.Zero;
                o.AwaitAnchorDelivery = true;
            });

            await AddCustomersAsync(harness, 1);

            Assert.Equal(4, publisher.Attempts);
            await using var db = harness.CreateContext();
            Assert.Single(await db.AuditLogs.ToListAsync());
        }

        [Fact]
        public async Task BackgroundDelivery_CanBeAwaited_WithFlush()
        {
            var publisher = new RecordingPublisher();
            var options = new TamperEvidentOptions
            {
                HmacSecretKey = Harness.SecretKey,
                CustomAnchorPublisher = publisher,
                AnchorThreshold = 1,
                AnchorRetryDelay = TimeSpan.Zero
            };
            var interceptor = new Interceptors.TamperEvidentInterceptor(options);

            using var connection = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
            connection.Open();
            var dbOptions = new DbContextOptionsBuilder<TestDbContext>().UseSqlite(connection).AddInterceptors(interceptor).Options;
            await using var db = new TestDbContext(dbOptions);
            await db.Database.EnsureCreatedAsync();

            db.Customers.Add(new Customer { Name = "background" });
            await db.SaveChangesAsync();
            await interceptor.FlushAnchorsAsync();

            Assert.Single(publisher.Published);
        }

        [Fact]
        public async Task PublishersWrittenForVersionOne_KeepWorking()
        {
            var publisher = new LegacyPublisher();
            using var harness = HarnessWith(publisher, threshold: 2);

            await AddCustomersAsync(harness, 2);

            var (table, hash, count) = Assert.Single(publisher.Sent);
            Assert.Equal("Customers", table);
            Assert.Equal(2, count);
            Assert.Equal(64, hash.Length);
        }

        [Fact]
        public async Task CompositePublisher_RetriesEachTargetOnItsOwn()
        {
            var healthy = new RecordingPublisher();
            var flaky = new RecordingPublisher(failFirst: 1);
            using var harness = HarnessWith(new CompositeAnchorPublisher(healthy, flaky), threshold: 1);

            await AddCustomersAsync(harness, 1);

            Assert.Equal(1, healthy.Attempts);
            Assert.Equal(2, flaky.Attempts);
            Assert.Single(healthy.Published);
            Assert.Single(flaky.Published);
        }

        [Fact]
        public async Task CompositePublisher_ReportsEveryFailure_WhenUsedDirectly()
        {
            var composite = new CompositeAnchorPublisher(new RecordingPublisher(int.MaxValue), new RecordingPublisher(int.MaxValue));
            var anchor = new AuditAnchor("T", new string('a', 64), 1, 1, DateTimeOffset.UtcNow);

            var ex = await Assert.ThrowsAsync<AggregateException>(() => composite.PublishAsync(anchor));
            Assert.Equal(2, ex.InnerExceptions.Count);
        }

        [Fact]
        public async Task FilePublisher_AppendsJsonLines_ThatCanBeReadBack()
        {
            var path = Path.Combine(Path.GetTempPath(), "te-anchors-" + Guid.NewGuid().ToString("N"), "anchors.jsonl");
            try
            {
                var publisher = new FileAnchorPublisher(path);
                var now = DateTimeOffset.UtcNow;
                await publisher.PublishAsync(new AuditAnchor("Customers", new string('a', 64), 10, 10, now));
                await publisher.PublishAsync(new AuditAnchor("Orders", new string('b', 64), 4, 4, now));

                var anchors = FileAnchorPublisher.ReadAnchors(path);
                Assert.Equal(2, anchors.Count);
                Assert.Equal("Customers", anchors[0].TableName);
                Assert.Equal(new string('b', 64), anchors[1].Hash);
                Assert.Equal(4, anchors[1].SequenceNumber);
                Assert.Equal(2, File.ReadAllLines(path).Length);
            }
            finally
            {
                Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
            }
        }

        [Fact]
        public async Task WebhookPublisher_PostsTheAnchor_WithAVerifiableSignature()
        {
            var handler = new CapturingHandler(HttpStatusCode.OK);
            var clock = new TestClock(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero));
            var publisher = new WebhookAnchorPublisher(new Uri("https://example.test/anchors"), "shared-signing-secret", new HttpClient(handler), clock);
            var anchor = new AuditAnchor("Customers", new string('c', 64), 42, 7, new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero));

            await publisher.PublishAsync(anchor);

            Assert.Equal(HttpMethod.Post, handler.Method);
            Assert.Equal("Customers", handler.Headers["X-TamperEvident-Table"]);
            Assert.Contains("\"hash\":\"" + new string('c', 64) + "\"", handler.Body);
            Assert.Contains("\"sequenceNumber\":42", handler.Body);

            // t=<unix time>,v1=HMAC("<unix time>." + body)
            var header = handler.Headers[WebhookAnchorPublisher.SignatureHeader];
            var expected = Convert.ToHexString(HMACSHA256.HashData(
                Encoding.UTF8.GetBytes("shared-signing-secret"), Encoding.UTF8.GetBytes("1767323045." + handler.Body))).ToLowerInvariant();
            Assert.Equal("t=1767323045,v1=" + expected, header);

            var body = Encoding.UTF8.GetBytes(handler.Body);
            Assert.True(WebhookAnchorPublisher.VerifySignature(header, body, "shared-signing-secret", timeProvider: clock));
            Assert.False(WebhookAnchorPublisher.VerifySignature(header, body, "another-secret", timeProvider: clock));
            Assert.False(WebhookAnchorPublisher.VerifySignature(header, Encoding.UTF8.GetBytes(handler.Body.Replace("42", "43")), "shared-signing-secret", timeProvider: clock));
            Assert.False(WebhookAnchorPublisher.VerifySignature(header.Replace("t=1767323045", "t=1767323046"), body, "shared-signing-secret", timeProvider: clock));
            Assert.False(WebhookAnchorPublisher.VerifySignature(null, body, "shared-signing-secret"));
            Assert.False(WebhookAnchorPublisher.VerifySignature("v1=abc", body, "shared-signing-secret"));

            // A replay an hour later is refused.
            clock.Advance(TimeSpan.FromHours(1));
            Assert.False(WebhookAnchorPublisher.VerifySignature(header, body, "shared-signing-secret", timeProvider: clock));
            Assert.True(WebhookAnchorPublisher.VerifySignature(header, body, "shared-signing-secret", TimeSpan.FromHours(2), clock));
        }

        [Theory]
        [InlineData("t=99999999999999,v1=")]
        [InlineData("t=253402300800,v1=")]
        [InlineData("t=9223372036854775807,v1=")]
        public void WebhookSignature_WithAnOutOfRangeTimestamp_IsRejected_NotThrown(string prefix)
        {
            // An attacker controls the header: a timestamp beyond DateTimeOffset.MaxValue must not turn into a 500.
            var header = prefix + new string('a', 64);
            Assert.False(WebhookAnchorPublisher.VerifySignature(header, "{}"u8, "shared-signing-secret"));
        }

        [Fact]
        public async Task WebhookPublisher_ThrowsOnErrorStatus_SoThatTheDispatcherRetries()
        {
            var publisher = new WebhookAnchorPublisher(new Uri("https://example.test/anchors"), null, new HttpClient(new CapturingHandler(HttpStatusCode.BadGateway)));
            var anchor = new AuditAnchor("Customers", new string('c', 64), 1, 1, DateTimeOffset.UtcNow);

            await Assert.ThrowsAsync<HttpRequestException>(() => publisher.PublishAsync(anchor));
        }

        [Fact]
        public async Task WebhookPublisher_WithoutSecret_SendsNoSignature()
        {
            var handler = new CapturingHandler(HttpStatusCode.NoContent);
            var publisher = new WebhookAnchorPublisher(new Uri("https://example.test/anchors"), null, new HttpClient(handler));

            await publisher.PublishAsync(new AuditAnchor("T", new string('d', 64), 1, 1, DateTimeOffset.UtcNow));

            Assert.False(handler.Headers.ContainsKey(WebhookAnchorPublisher.SignatureHeader));
        }

        [Fact]
        public void SmtpPublisher_RecognisesIncompleteConfiguration()
        {
            Assert.False(SmtpAnchorPublisher.IsConfigured(new TamperEvidentOptions()));
            Assert.False(SmtpAnchorPublisher.IsConfigured(new TamperEvidentOptions { SmtpHost = "smtp.test", SmtpUser = "bot@test" }));
            Assert.True(SmtpAnchorPublisher.IsConfigured(new TamperEvidentOptions
            {
                SmtpHost = "smtp.test", SmtpUser = "bot@test", AnchorEmailTo = "audit@test"
            }));
        }

        [Fact]
        public async Task SmtpPublisher_RefusesToRunUnconfigured_InsteadOfSilentlySkipping()
        {
            var publisher = new SmtpAnchorPublisher(new TamperEvidentOptions());
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => publisher.PublishAsync(new AuditAnchor("T", new string('e', 64), 1, 1, DateTimeOffset.UtcNow)));
        }

        [Fact]
        public void SmtpMail_ContainsTheHashTheSequenceAndTheCount()
        {
            var body = SmtpAnchorPublisher.BuildBody(new AuditAnchor("Customers", new string('f', 64), 1000, 250, DateTimeOffset.UtcNow));

            Assert.Contains("Table: Customers", body);
            Assert.Contains("Sequence: 1000", body);
            Assert.Contains("Total New Records: 250", body);
            Assert.Contains(new string('f', 64), body);
        }

        private static async Task WaitForAsync(Func<bool> condition)
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (!condition() && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20);
            }
        }

        private sealed class CapturingHandler : HttpMessageHandler
        {
            private readonly HttpStatusCode _status;

            public CapturingHandler(HttpStatusCode status) => _status = status;

            public HttpMethod? Method { get; private set; }

            public string Body { get; private set; } = string.Empty;

            public Dictionary<string, string> Headers { get; } = new();

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Method = request.Method;
                Body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
                foreach (var header in request.Headers)
                {
                    Headers[header.Key] = string.Join(",", header.Value);
                }

                return new HttpResponseMessage(_status);
            }
        }
    }
}
