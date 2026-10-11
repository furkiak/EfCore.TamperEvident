using System.Text.Json;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Tests
{
    public enum Status
    {
        Draft = 0,
        Published = 1
    }

    public class Author
    {
        public int Id { get; set; }
        public required string Name { get; set; }
        public List<Book> Books { get; set; } = new();
    }

    public class Book
    {
        public int Id { get; set; }
        public required string Title { get; set; }
        public Status Status { get; set; }
        public DateOnly Released { get; set; }
        public TimeOnly OpensAt { get; set; }
        public DateTimeOffset UpdatedAt { get; set; }
        public double Rating { get; set; }
        public Author? Author { get; set; }          // navigation cycle: Author.Books <-> Book.Author
        public List<Tag> Tags { get; set; } = new(); // many-to-many
        public Address? Shipping { get; set; }       // owned type, same table
    }

    public class Tag
    {
        public int Id { get; set; }
        public required string Label { get; set; }
        public List<Book> Books { get; set; } = new();
    }

    public class Address
    {
        public string? Street { get; set; }
        public string? City { get; set; }
    }

    public abstract class Vehicle
    {
        public int Id { get; set; }
        public required string Plate { get; set; }
    }

    public class Car : Vehicle
    {
        public int Doors { get; set; }
    }

    public class Truck : Vehicle
    {
        public double PayloadTons { get; set; }
    }

    public class ShopDb : DbContext
    {
        private readonly SqliteConnection _connection;
        private readonly TamperEvidentOptions _options;

        public ShopDb(SqliteConnection connection, TamperEvidentOptions options)
        {
            _connection = connection;
            _options = options;
        }

        public DbSet<Author> Authors => Set<Author>();

        public DbSet<Book> Books => Set<Book>();

        public DbSet<Vehicle> Vehicles => Set<Vehicle>();

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder) =>
            optionsBuilder.UseSqlite(_connection).UseTamperEvidentAudit(_options);

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.ApplyTamperEvidentAudit();
            modelBuilder.Entity<Book>().OwnsOne(b => b.Shipping);
            modelBuilder.Entity<Book>().Property(b => b.Status).HasConversion<string>();
            modelBuilder.Entity<Book>().HasMany(b => b.Tags).WithMany(t => t.Books);
            modelBuilder.Entity<Vehicle>().HasDiscriminator<string>("Kind").HasValue<Car>("car").HasValue<Truck>("truck");
        }
    }

    public class ModelFeatureTests : IDisposable
    {
        private readonly SqliteConnection _connection = new("DataSource=:memory:");
        private readonly TamperEvidentOptions _options = new() { HmacSecretKey = Harness.SecretKey };

        public ModelFeatureTests()
        {
            _connection.Open();
            using var db = Create();
            db.Database.EnsureCreated();
        }

        private ShopDb Create() => new(_connection, _options);

        public void Dispose()
        {
            _connection.Dispose();
            GC.SuppressFinalize(this);
        }

        [Fact]
        public async Task EntityGraphsWithNavigationCycles_AreAudited_WithoutSerializationErrors()
        {
            // Regression: serializing the whole entity graph threw "possible object cycle was detected".
            await using (var db = Create())
            {
                var author = new Author { Name = "Ada" };
                var book = new Book { Title = "Notes", Author = author, Released = new DateOnly(1843, 1, 1) };
                author.Books.Add(book);
                db.Authors.Add(author);
                await db.SaveChangesAsync();
            }

            await using var verify = Create();
            var result = await new Services.AuditVerifier(verify, _options).VerifyAllAsync();
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(2, result.RecordsChecked);

            var bookLog = await verify.Set<AuditLog>().SingleAsync(l => l.TableName == "Books");
            using var json = JsonDocument.Parse(bookLog.NewValues!);

            // The foreign key (a shadow property) is audited; the navigations are not.
            Assert.Equal(1, json.RootElement.GetProperty("AuthorId").GetInt32());
            Assert.False(json.RootElement.TryGetProperty("Author", out _));
            Assert.False(json.RootElement.TryGetProperty("Tags", out _));
        }

        [Fact]
        public async Task EnumsDatesAndFloatingPointValues_AreWrittenInAStableReadableForm()
        {
            await using (var db = Create())
            {
                db.Books.Add(new Book
                {
                    Title = "Types",
                    Status = Status.Published,
                    Released = new DateOnly(2026, 5, 17),
                    OpensAt = new TimeOnly(9, 30),
                    UpdatedAt = new DateTimeOffset(2026, 5, 17, 12, 0, 0, TimeSpan.FromHours(3)),
                    Rating = 4.5
                });
                await db.SaveChangesAsync();
            }

            await using var verify = Create();
            var json = (await verify.Set<AuditLog>().SingleAsync()).NewValues!;
            using var doc = JsonDocument.Parse(json);

            Assert.Equal("Published", doc.RootElement.GetProperty("Status").GetString());
            Assert.Equal("2026-05-17", doc.RootElement.GetProperty("Released").GetString());
            Assert.Equal("09:30:00", doc.RootElement.GetProperty("OpensAt").GetString());
            Assert.Equal(4.5, doc.RootElement.GetProperty("Rating").GetDouble());
            Assert.StartsWith("2026-05-17T12:00:00", doc.RootElement.GetProperty("UpdatedAt").GetString());
        }

        [Fact]
        public async Task ManyToManyJoinRows_AreAudited()
        {
            await using (var db = Create())
            {
                var book = new Book { Title = "Tagged" };
                book.Tags.Add(new Tag { Label = "classic" });
                book.Tags.Add(new Tag { Label = "science" });
                db.Books.Add(book);
                await db.SaveChangesAsync();
            }

            await using var verify = Create();
            var logs = await verify.Set<AuditLog>().ToListAsync();

            Assert.Contains(logs, l => l.TableName == "BookTag" && l.ActionType == AuditActions.Added && l.RecordId == "1|1");
            Assert.Equal(2, logs.Count(l => l.TableName == "BookTag"));
            Assert.True((await new Services.AuditVerifier(verify, _options).VerifyAllAsync()).IsValid);
        }

        [Fact]
        public async Task OwnedTypes_AreAuditedWithTheKeyOfTheirOwner()
        {
            await using (var db = Create())
            {
                db.Books.Add(new Book { Title = "Owned", Shipping = new Address { Street = "Main St", City = "Istanbul" } });
                await db.SaveChangesAsync();
            }

            await using (var db = Create())
            {
                (await db.Books.Include(b => b.Shipping).SingleAsync()).Shipping!.City = "Ankara";
                await db.SaveChangesAsync();
            }

            await using var verify = Create();
            var update = await verify.Set<AuditLog>().SingleAsync(l => l.ActionType == AuditActions.Modified);

            Assert.Equal("Books", update.TableName);
            Assert.Equal("1", update.RecordId);
            Assert.Contains("Ankara", update.NewValues);
            Assert.Contains("Istanbul", update.OldValues);
        }

        [Fact]
        public async Task InheritanceHierarchies_ShareOneChain()
        {
            await using (var db = Create())
            {
                db.Vehicles.Add(new Car { Plate = "34 ABC 123", Doors = 5 });
                db.Vehicles.Add(new Truck { Plate = "06 XYZ 987", PayloadTons = 12.5 });
                await db.SaveChangesAsync();
            }

            await using var verify = Create();
            var logs = await verify.Set<AuditLog>().OrderBy(l => l.SequenceNumber).ToListAsync();

            Assert.All(logs, l => Assert.Equal("Vehicles", l.TableName));
            Assert.Equal(2, logs.Count);
            Assert.Contains(logs, l => l.NewValues!.Contains("Doors"));
            Assert.Contains(logs, l => l.NewValues!.Contains("PayloadTons"));
            Assert.Contains(logs, l => l.NewValues!.Contains("\"Kind\":\"car\""));
        }

        [Fact]
        public async Task TheOriginalEntityIsNotInstantiated_SoEntitiesWithoutAParameterlessConstructorWork()
        {
            // Regression: the old implementation created a copy of every entity with its constructor.
            await using var db = Create();
            db.Set<Tag>().Add(new Tag { Label = "x" });
            await db.SaveChangesAsync();
            Assert.Single(await db.Set<AuditLog>().ToListAsync());
        }
    }
}
