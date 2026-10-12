using System.Security.Claims;
using EfCore.TamperEvident;
using EfCore.TamperEvident.AspNetCore;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using QuickStart;

var builder = WebApplication.CreateBuilder(args);

// In a real application the secret comes from a key vault or an environment variable - never from the source code.
var secretKey = builder.Configuration["TamperEvident:SecretKey"] ?? "quickstart-demo-secret-change-me-0123456789abcdef";
var dataDirectory = Path.Combine(builder.Environment.ContentRootPath, "App_Data");
Directory.CreateDirectory(dataDirectory);
var connectionString = $"Data Source={Path.Combine(dataDirectory, "quickstart.db")}";
var anchorFile = Path.Combine(dataDirectory, "anchors.jsonl");

// 1. Audit trail ---------------------------------------------------------------------------------------------------
builder.Services.AddHttpContextAccessor();
builder.Services.AddTamperEvident((sp, audit) =>
{
    audit.HmacSecretKey = secretKey;
    audit.UseHttpContextUser(sp);                         // who changed it: the authenticated user of the request
    audit.UseHttpRequestMetadata(sp);                     // from where: client IP, user agent and request (redactable)
    audit.AnchorThreshold = 25;                           // publish an anchor every 25 entries per table...
    audit.CustomAnchorPublisher = new FileAnchorPublisher(anchorFile); // ...to a place the database cannot reach
});
builder.Services.AddDbContext<AppDbContext>((sp, options) => options.UseSqlite(connectionString).UseTamperEvidentAudit(sp));

// 2. Scheduled verification + health check ----------------------------------------------------------------------------
builder.Services.AddTamperEvidentVerification<AppDbContext>(options =>
{
    options.Interval = TimeSpan.FromMinutes(1);
    options.InitialDelay = TimeSpan.FromSeconds(5);
    options.AnchorProvider = AnchorSources.FromFile(anchorFile);
});
builder.Services.AddHealthChecks().AddTamperEvidentHealthCheck();

// 3. Authentication: the dashboard must never be public --------------------------------------------------------------
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
builder.Services.AddAuthorizationBuilder().AddPolicy("Auditors", policy => policy.RequireRole("Auditor"));

var app = builder.Build();

await DemoData.SeedAsync(connectionString, secretKey, anchorFile);

app.UseAuthentication();
app.UseAuthorization();

// The dashboard: https://localhost:5001/audit
app.MapTamperEvidentDashboard<AppDbContext>("/audit", options =>
{
    options.Title = "Acme Audit";
    options.AnchorProvider = AnchorSources.FromFile(anchorFile);
}).RequireAuthorization("Auditors");

app.MapHealthChecks("/health");

// A tiny API: every change below is audited automatically, attributed to the signed-in user.
app.MapGet("/", () => Results.Text("""
    EfCore.TamperEvident quick start

      GET  /login/alice          sign in as an auditor (demo only)
      GET  /audit                the audit dashboard
      GET  /health               health check (includes the latest integrity verification)
      GET  /customers            list customers
      POST /customers            create a customer   {"name":"Ada"}
      PUT  /customers/{id}       change a customer   {"company":"Acme"}
      DELETE /customers/{id}     delete a customer
      GET  /customers/{id}/history          who changed what, when and why
      GET  /customers/{id}/as-of?time=...   the customer as it was at a point in time
      POST /customers/{id}/erase            GDPR / KVKK erasure: redact personal data, keep the chain verifiable
      POST /demo/tamper          simulate a database administrator rewriting history (watch the dashboard turn red)
      POST /demo/repair          undo the simulated attack
    """));

app.MapGet("/login/{user}", async (string user, HttpContext http) =>
{
    var identity = new ClaimsIdentity(
        [new Claim(ClaimTypes.Name, user), new Claim(ClaimTypes.Role, "Auditor")],
        CookieAuthenticationDefaults.AuthenticationScheme);
    await http.SignInAsync(new ClaimsPrincipal(identity));
    return Results.Redirect("/audit");
});

app.MapGet("/customers", (AppDbContext db) => db.Customers.AsNoTracking().OrderBy(c => c.Id).Take(100).ToListAsync());

app.MapPost("/customers", async (CustomerInput input, AppDbContext db) =>
{
    var customer = new Customer { Name = input.Name ?? "Unnamed", Email = input.Email, Company = input.Company };
    db.Customers.Add(customer);
    await db.SaveChangesAsync();
    return Results.Created($"/customers/{customer.Id}", customer);
}).RequireAuthorization();

app.MapPut("/customers/{id:int}", async (int id, CustomerInput input, AppDbContext db) =>
{
    var customer = await db.Customers.FindAsync(id);
    if (customer is null)
    {
        return Results.NotFound();
    }

    customer.Name = input.Name ?? customer.Name;
    customer.Email = input.Email ?? customer.Email;
    customer.Company = input.Company ?? customer.Company;

    // The reason is sealed into the audit entry together with the change.
    using (input.Reason is null ? null : AuditScope.WithReason(input.Reason))
    {
        await db.SaveChangesAsync();
    }

    return Results.Ok(customer);
}).RequireAuthorization();

app.MapGet("/customers/{id:int}/history", async (int id, AppDbContext db) =>
    (await db.GetAuditTrailAsync("Customers", id.ToString(System.Globalization.CultureInfo.InvariantCulture)))
        .Select(change => new
        {
            change.SequenceNumber,
            change.Action,
            change.UserId,
            change.TimestampUtc,
            change.Reason,
            changes = change.Changes.Select(c => new { c.Property, from = c.OldValue.ToString(), to = c.NewValue.ToString() })
        })).RequireAuthorization();

app.MapGet("/customers/{id:int}/as-of", async (int id, DateTimeOffset time, AppDbContext db) =>
{
    var snapshot = await db.GetStateAsOfAsync("Customers", id.ToString(System.Globalization.CultureInfo.InvariantCulture), time);
    return snapshot.Exists ? Results.Ok(snapshot.ToObject<Customer>()) : Results.NotFound();
}).RequireAuthorization();

app.MapPost("/customers/{id:int}/erase", async (int id, AppDbContext db) =>
{
    var result = await db.RedactAuditTrailAsync("Customers", id.ToString(System.Globalization.CultureInfo.InvariantCulture), new AuditRedactionRequest
    {
        Reason = $"Erasure request for customer {id}",
        Properties = ["Name", "Email", "CardNumber"],
        MetadataKeys = ["ip", "userAgent"]
    });
    return Results.Ok(result);
}).RequireAuthorization();

app.MapDelete("/customers/{id:int}", async (int id, AppDbContext db) =>
{
    var customer = await db.Customers.FindAsync(id);
    if (customer is null)
    {
        return Results.NotFound();
    }

    db.Customers.Remove(customer);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();

// --- Demo only: play the attacker -------------------------------------------------------------------------------------
if (app.Environment.IsDevelopment())
{
    string? originalUser = null;

    app.MapPost("/demo/tamper", async (AppDbContext db) =>
    {
        // Direct SQL: no interceptor, no secret key. Exactly what a rogue DBA can do.
        originalUser ??= await db.Database
            .SqlQueryRaw<string>("SELECT UserId AS Value FROM AuditLogs WHERE TableName = 'Customers' AND SequenceNumber = 7")
            .FirstOrDefaultAsync();
        var affected = await db.Database.ExecuteSqlRawAsync(
            "UPDATE AuditLogs SET UserId = 'mallory' WHERE TableName = 'Customers' AND SequenceNumber = 7");
        return Results.Ok(new { affected, note = "Entry 7 of Customers now claims it was written by 'mallory'. Run a verification in the dashboard." });
    });

    app.MapPost("/demo/repair", async (AppDbContext db) =>
    {
        var affected = originalUser is null
            ? 0
            : await db.Database.ExecuteSqlRawAsync(
                "UPDATE AuditLogs SET UserId = {0} WHERE TableName = 'Customers' AND SequenceNumber = 7", originalUser);
        originalUser = null;
        return Results.Ok(new { affected, note = "The original entry was restored." });
    });
}

app.Run();

internal sealed record CustomerInput(string? Name, string? Email, string? Company, string? Reason);
