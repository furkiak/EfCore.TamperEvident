using EfCore.TamperEvident;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;

namespace QuickStart;

/// <summary>Creates a believable ten-day history so that the dashboard has something to show.</summary>
public static class DemoData
{
    public static async Task SeedAsync(string connectionString, string secretKey, string anchorFile)
    {
        await using (var setup = new AppDbContext(Options(connectionString, new TamperEvidentOptions { HmacSecretKey = secretKey })))
        {
            await setup.Database.EnsureCreatedAsync();
            if (await setup.Customers.AnyAsync())
            {
                return;
            }
        }

        // A clock that moves forward between saves, so entries are spread over the last two weeks.
        var clock = new SteppingClock(DateTimeOffset.UtcNow.AddDays(-10));
        var options = new TamperEvidentOptions
        {
            HmacSecretKey = secretKey,
            TimeProvider = clock,
            AnchorThreshold = 25,
            CustomAnchorPublisher = new EfCore.TamperEvident.Services.FileAnchorPublisher(anchorFile),
            AwaitAnchorDelivery = true
        };
        var random = new Random(42);
        string[] addresses = ["203.0.113.7", "198.51.100.23", "192.0.2.41", "203.0.113.150"];
        options.MetadataProvider = _ => new Dictionary<string, object?> { ["ip"] = addresses[random.Next(addresses.Length)] };
        string[] reasons = ["Customer called to update the account", "Annual credit review", "Data quality fix (ticket #4711)", "Requested by the account manager"];

        string[] people = ["alice", "bob", "carol", "dave"];
        string[] companies = ["Acme Corp", "Globex", "Initech", "Umbrella Ltd", "Hooli", "Stark Industries", "Wayne Enterprises", "Soylent"];
        string[] names = ["Ada Lovelace", "Alan Turing", "Grace Hopper", "Linus Torvalds", "Margaret Hamilton", "Dennis Ritchie", "Barbara Liskov", "Ken Thompson", "Radia Perlman", "Donald Knuth", "Edsger Dijkstra", "Katherine Johnson"];

        await using var db = new AppDbContext(Options(connectionString, options));

        var customers = new List<Customer>();
        foreach (var name in names)
        {
            clock.Advance(TimeSpan.FromMinutes(random.Next(60, 260)));
            using (AuditScope.Begin(people[random.Next(people.Length)]))
            {
                var customer = new Customer
                {
                    Name = name,
                    Email = name.ToLowerInvariant().Replace(' ', '.') + "@example.com",
                    Company = companies[random.Next(companies.Length)],
                    CreditLimit = random.Next(1, 20) * 500,
                    CardNumber = "4111" + random.Next(100000000, 999999999) + "11",
                    PasswordHash = Guid.NewGuid().ToString("N")
                };
                db.Customers.Add(customer);
                await db.SaveChangesAsync();
                customers.Add(customer);
            }
        }

        for (var i = 0; i < 70; i++)
        {
            clock.Advance(TimeSpan.FromMinutes(random.Next(40, 280)));
            var user = people[random.Next(people.Length)];
            using (AuditScope.Begin(user, random.Next(3) == 0 ? reasons[random.Next(reasons.Length)] : null))
            {
                var customer = customers[random.Next(customers.Count)];
                switch (random.Next(10))
                {
                    case 0 or 1 or 2:
                        db.Invoices.Add(new Invoice
                        {
                            CustomerId = customer.Id,
                            Number = $"INV-{2026}-{1000 + i}",
                            Amount = random.Next(50, 9000),
                            Status = "Draft"
                        });
                        break;
                    case 3 or 4:
                        var draft = await db.Invoices.FirstOrDefaultAsync(x => x.Status == "Draft");
                        if (draft is not null)
                        {
                            draft.Status = random.Next(2) == 0 ? "Sent" : "Paid";
                            draft.Amount += random.Next(0, 200);
                        }

                        break;
                    case 5 or 6:
                        customer.CreditLimit += random.Next(-4, 6) * 250;
                        customer.Company = companies[random.Next(companies.Length)];
                        break;
                    case 7:
                        customer.Email = "new." + customer.Email;
                        customer.CardNumber = "5500" + random.Next(100000000, 999999999) + "00";
                        break;
                    case 8:
                        customer.IsDeleted = !customer.IsDeleted;
                        break;
                    default:
                        var stale = await db.Invoices.FirstOrDefaultAsync(x => x.Status == "Paid");
                        if (stale is not null)
                        {
                            db.Invoices.Remove(stale);
                        }

                        break;
                }

                await db.SaveChangesAsync();
            }
        }

        // An erasure request: the personal data of one customer leaves the trail, the chain stays verifiable.
        clock.Advance(TimeSpan.FromHours(3));
        using (AuditScope.Begin("dpo@acme.example"))
        {
            await db.RedactAuditTrailAsync(customers[^1], new AuditRedactionRequest
            {
                Reason = "Erasure request #2026-014 (GDPR Art. 17)",
                Properties = ["Name", "Email", "CardNumber"],
                MetadataKeys = ["ip"]
            });
        }
    }

    public static DbContextOptions<AppDbContext> Options(string connectionString, TamperEvidentOptions audit) =>
        new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connectionString).UseTamperEvidentAudit(audit).Options;

    private sealed class SteppingClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public void Advance(TimeSpan by) => _now += by;

        // Never in the future, whatever the steps add up to.
        public override DateTimeOffset GetUtcNow() => _now < DateTimeOffset.UtcNow ? _now : DateTimeOffset.UtcNow;
    }
}
