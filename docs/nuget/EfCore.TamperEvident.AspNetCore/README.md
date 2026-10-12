![The audit dashboard](https://raw.githubusercontent.com/furkiak/EfCore.TamperEvident/main/docs/assets/dashboard-light.jpg)

# EfCore.TamperEvident.AspNetCore

ASP.NET Core integration for [EfCore.TamperEvident](https://www.nuget.org/packages/EfCore.TamperEvident), the tamper-evident
audit trail for Entity Framework Core:

- 🪟 **A Liquid Glass dashboard**: integrity verdict, the hash chain with the broken block highlighted, activity, a filterable
  audit trail with property-by-property diffs, the history of a record on a timeline, verification against anchors, and exports
  (CSV, JSON Lines, evidence bundles). Light and dark, keyboard friendly, no build step, nothing loaded from the internet.
- ⏱ **Scheduled verification**: incremental every hour, a full verification every day, and your alarm when something is wrong.
- 🩺 **A health check** that reports the latest verification on `/health`.
- 👤 **HTTP attribution**: the signed-in user, and optionally the client IP, user agent and request of every change.

## Setup

```csharp
builder.Services.AddHttpContextAccessor();
builder.Services.AddTamperEvident((sp, audit) =>
{
    audit.HmacSecretKey = builder.Configuration["TamperEvident:SecretKey"]!;
    audit.UseHttpContextUser(sp);           // who
    audit.UseHttpRequestMetadata(sp);       // from where: ip, userAgent, "POST /orders/42"
});
builder.Services.AddDbContext<AppDbContext>((sp, options) => options.UseNpgsql(connectionString).UseTamperEvidentAudit(sp));

builder.Services.AddTamperEvidentVerification<AppDbContext>(options =>
{
    options.OnTamperDetected = (report, services, ct) =>
    {
        services.GetRequiredService<ILogger<Program>>().LogCritical("TAMPERING: {Message}", report.Message);
        return Task.CompletedTask;                                    // or page someone
    };
});
builder.Services.AddHealthChecks().AddTamperEvidentHealthCheck();

var app = builder.Build();
app.MapTamperEvidentDashboard<AppDbContext>("/audit").RequireAuthorization("Auditors");
app.MapHealthChecks("/health");
```

**Secure by default.** Outside of `Development` the dashboard refuses to serve unless it is protected with
`RequireAuthorization(...)` (or explicitly opened with `AllowAnonymous = true`, for example behind an authenticating proxy).
It sends a strict Content-Security-Policy, `no-store` API responses and requires an anti-CSRF header on every state-changing
request. Exports can be switched off with `AllowExport = false`.

![Tampering detected](https://raw.githubusercontent.com/furkiak/EfCore.TamperEvident/main/docs/assets/dashboard-tampered.jpg)

## Documentation

- [Full documentation](https://github.com/furkiak/EfCore.TamperEvident#readme) · [Türkçe](https://github.com/furkiak/EfCore.TamperEvident/blob/main/README.tr.md)
- [The dashboard](https://github.com/furkiak/EfCore.TamperEvident#the-dashboard) · [Configuration reference](https://github.com/furkiak/EfCore.TamperEvident#configuration-reference)
- [Changelog](https://github.com/furkiak/EfCore.TamperEvident/blob/main/CHANGELOG.md) · [Issues](https://github.com/furkiak/EfCore.TamperEvident/issues)
