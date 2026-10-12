using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;

namespace EfCore.TamperEvident.Tests
{
    /// <summary>The readable history of a row and its values at a point in time.</summary>
    public class HistoryTests
    {
        private static readonly DateTimeOffset Start = new(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

        private static async Task<(Harness Harness, TestClock Clock, Customer Customer)> HistoryAsync()
        {
            var clock = new TestClock(Start);
            var harness = new Harness(o => o.TimeProvider = clock);
            var customer = new Customer { Name = "Ayşe", Email = "ayse@example.com", Balance = 10, CardNumber = "4111111111111111" };

            await using (var db = harness.CreateContext())
            using (AuditScope.Begin("alice"))
            {
                db.Customers.Add(customer);
                await db.SaveChangesAsync();
            }

            clock.Advance(TimeSpan.FromDays(1));
            await using (var db = harness.CreateContext())
            using (AuditScope.Begin("bob", "Customer moved (ticket #7)"))
            {
                db.Attach(customer);
                customer.Email = "ayse@new.example.com";
                customer.Balance = 25.5m;
                await db.SaveChangesAsync();
            }

            clock.Advance(TimeSpan.FromDays(1));
            await using (var db = harness.CreateContext())
            {
                db.Attach(customer);
                customer.IsDeleted = true;
                await db.SaveChangesAsync();
            }

            clock.Advance(TimeSpan.FromDays(1));
            await using (var db = harness.CreateContext())
            {
                db.Attach(customer);
                db.Remove(customer);
                await db.SaveChangesAsync();
            }

            return (harness, clock, customer);
        }

        [Fact]
        public async Task TheTrail_ListsEveryChange_PropertyByProperty()
        {
            var (harness, _, customer) = await HistoryAsync();
            using var _ = harness;
            await using var db = harness.CreateContext();

            var trail = await db.GetAuditTrailAsync(customer);

            Assert.Equal(new[] { AuditActions.Added, AuditActions.Modified, AuditActions.SoftDelete, AuditActions.Deleted }, trail.Select(c => c.Action));
            Assert.Equal(new[] { 1L, 2, 3, 4 }, trail.Select(c => c.SequenceNumber));

            var insert = trail[0];
            Assert.Equal("alice", insert.UserId);
            Assert.Equal(Start.UtcDateTime, insert.TimestampUtc);
            Assert.All(insert.Changes, c => Assert.True(c.OldValue.IsMissing));
            Assert.Equal("Ayşe", insert.Changes.Single(c => c.Property == "Name").NewValue.As<string>());
            Assert.True(insert.Changes.Single(c => c.Property == "CardNumber").NewValue.IsMasked);
            Assert.DoesNotContain(insert.Changes, c => c.Property == "PasswordHash"); // [AuditIgnore]

            var update = trail[1];
            Assert.Equal("bob", update.UserId);
            Assert.Equal("Customer moved (ticket #7)", update.Reason);
            Assert.Equal(new[] { "Balance", "Email" }, update.Changes.Select(c => c.Property));
            var balance = update.Changes[0];
            Assert.Equal(10m, balance.OldValue.As<decimal>());
            Assert.Equal(25.5m, balance.NewValue.As<decimal>());
            Assert.Equal("ayse@example.com → ayse@new.example.com", $"{update.Changes[1].OldValue} → {update.Changes[1].NewValue}");

            var delete = trail[3];
            Assert.All(delete.Changes, c => Assert.True(c.NewValue.IsMissing));
        }

        [Fact]
        public async Task TheStateAsOf_ReplaysTheHistory()
        {
            var (harness, _, customer) = await HistoryAsync();
            using var _ = harness;
            await using var db = harness.CreateContext();

            var before = await db.GetStateAsOfAsync(customer, Start.AddMinutes(-1));
            Assert.False(before.Exists);
            Assert.Null(before.EntryId);

            var first = await db.GetStateAsOfAsync(customer, Start.AddHours(12));
            Assert.True(first.Exists);
            Assert.Equal("ayse@example.com", first.Values["Email"].As<string>());

            var second = await db.GetStateAsOfAsync(customer, Start.AddDays(1).AddHours(1));
            var entity = second.ToObject<Customer>()!;
            Assert.Equal("ayse@new.example.com", entity.Email);
            Assert.Equal(25.5m, entity.Balance);
            Assert.Equal("Ayşe", entity.Name);
            Assert.Null(entity.CardNumber); // masked values are not materialized
            Assert.False(entity.IsDeleted);

            var softDeleted = (await db.GetStateAsOfAsync(customer, Start.AddDays(2).AddHours(1))).ToObject<Customer>()!;
            Assert.True(softDeleted.IsDeleted);

            var gone = await db.GetStateAsOfAsync(customer, Start.AddDays(10));
            Assert.False(gone.Exists);
            Assert.Null(gone.ToObject<Customer>());
        }

        [Fact]
        public async Task RedactedValues_ShowUpAsRedacted()
        {
            var (harness, _, customer) = await HistoryAsync();
            using var _ = harness;

            await using (var db = harness.CreateContext())
            {
                await db.RedactAuditTrailAsync(customer, new AuditRedactionRequest { Reason = "GDPR", Properties = new[] { "Email" } });
            }

            await using (var read = harness.CreateContext())
            {
                var trail = await read.GetAuditTrailAsync(customer);
                Assert.Equal(AuditActions.Redacted, trail[^1].Action);
                Assert.Equal("GDPR", trail[^1].Reason);
                Assert.Empty(trail[^1].Changes);

                var email = trail[0].Changes.Single(c => c.Property == "Email").NewValue;
                Assert.True(email.IsRedacted);
                Assert.Equal("[redacted]", email.ToString());
                Assert.Null(email.As<string>());

                var snapshot = await read.GetStateAsOfAsync(customer, Start.AddHours(1));
                Assert.Null(snapshot.ToObject<Customer>()!.Email);
            }
        }

        [Fact]
        public void AuditValues_CompareByKindAndJson()
        {
            using var document = System.Text.Json.JsonDocument.Parse("[1, 1, \"[MASKED:abcd1234]\", null]");
            var items = document.RootElement.EnumerateArray().Select(AuditValue.From).ToList();
            Assert.Equal(items[0], items[1]);
            Assert.True(items[0] == items[1]);
            Assert.True(items[2].IsMasked);
            Assert.Equal(AuditValueKind.Null, items[3].Kind);
            Assert.Equal("null", items[3].ToString());
            Assert.NotEqual(AuditValue.Missing, items[3]);
        }
    }
}
