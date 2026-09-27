# EF Core Tamper-Evident

An EF Core audit trail that links row changes with HMAC-SHA256 and can export periodic hashes to a separate trust boundary. It records inserts, updates and deletes on both `SaveChanges()` and `SaveChangesAsync()`, including database-generated primary keys.

![Audit flow from business change through the HMAC chain and external anchor](docs/architecture.svg)

> **Release status:** this branch is the **unpublished 2.0.0 preview**. NuGet 1.0.1 uses a different hash and configuration format. Do not apply this branch to an existing 1.x audit database without a reviewed migration. SQL Server has real integration coverage; PostgreSQL and MySQL are not yet integration-verified.

## Why it exists

Ordinary application logs can be edited along with the records they describe. This library places each audit entry in a per-table chain:

```text
business row -> audit entry -> HMAC(previous hash + complete audit identity and payload)
                                     |
                             next audit entry
                                     |
                           pending external anchor
```

The HMAC covers the audit ID, table, composite record key, action, old and new values, actor, timestamp and previous hash. Fields are length-framed so two different records cannot hash to the same byte sequence by ambiguous concatenation. When an anchor is delivered and retained outside the database, a verifier can detect a rewritten or truncated chain relative to that trusted anchor.

This is **tamper evidence**, not a guarantee that the database cannot be changed. The protection depends on an application-held secret that database administrators cannot read and on independently retained external anchors. Verification without external anchors cannot prove that the whole history was not replaced by someone who also has the HMAC key. The audit payload is plaintext: configure access control, retention and redaction for your data.

## Requirements

- .NET 9, EF Core 9 and a relational EF provider
- A base64-encoded, randomly generated HMAC key of at least 32 bytes, stored outside source control and outside the audited database
- Three mapped tables: `AuditLogs`, `AuditChainStates` and `PendingAnchors`
- A scheduled call to `AnchorDispatcher` if external anchoring is enabled

Generate a key once with `RandomNumberGenerator.GetBytes(32)`, convert it with `Convert.ToBase64String`, and store it in a production secret manager. Do not rotate it without preserving the previous key and a verified migration strategy: existing hashes require the original key.

The [key lifecycle plan](docs/KEY_LIFECYCLE.md) explains host secret-manager integration, operational key identities, separate-chain rotation and read-only verification of 1.x history. Per-row key rotation and in-place 1.x migration are not supported.

## Quick start

Build the unpublished preview locally with `dotnet pack -c Release`. For the published 1.0.1 package, use its matching tag and documentation.

For a complete runnable example against an **isolated test SQL Server**, run:

```powershell
$env:EFCORE_AUDIT_SQLSERVER='Server=.\SQLEXPRESS;Integrated Security=true;TrustServerCertificate=true;Encrypt=true'
dotnet run --project samples/SqlServerDemo -c Release
```

The sample creates a uniquely named `AuditDemo_*` database, inserts one synthetic customer, verifies the internal chain and pending anchor, and deletes its database in `finally`. Expected output includes `Business rows: 1; audit rows: 1` and `Pending anchors: 1; delivered: 0`. It does not send email or verify an independent anchor. Its ephemeral random key is never printed; use a retained secret-manager key and reviewed migrations for a retained application database. The test-only certificate exception is not a production TLS recommendation.

```csharp
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<Customer> Customers => Set<Customer>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.AddTamperEvidentModels();
    }
}
```

```csharp
builder.Services.AddDbContext<AppDbContext>((services, options) =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("App"));
    options.UseTamperEvidentAudit(audit =>
    {
        audit.HmacSecretKey = builder.Configuration["Audit:HmacKey"]
            ?? throw new InvalidOperationException("Audit:HmacKey is missing");
        audit.AnchorThreshold = 500;
        audit.UserIdProvider = _ => services
            .GetRequiredService<IHttpContextAccessor>()
            .HttpContext?.User.Identity?.Name ?? "System";
    });
});
```

Add `IHttpContextAccessor` if you use this actor example, generate an EF migration, review it, and apply it before writing audited entities. The library deliberately fails when audit models or the key are missing. A change and its audit entries are written in one transaction; an audit failure rolls back the business change. If the caller owns the transaction, the library leaves a successful transaction open for the caller. On an audit failure, it rolls back even that caller-owned transaction to prevent an unaudited commit. Use a fresh `DbContext` after a rolled-back transaction.

Audited saves require the default `acceptAllChangesOnSuccess: true`. `SaveChanges(false)` and `SaveChangesAsync(false)` are rejected with a transaction rollback: leaving business entries in a pending state would cause the internal audit save to write them a second time. This is a current API limit, including when the caller owns the transaction. Use a fresh context after this rejection.

The package redacts common secret-named properties such as `Password`, `ApiKey` and `Token` in old/new snapshots. Extend `RedactedProperties` for your domain. Record IDs, actor IDs and other properties can still contain personal data; review your schema before enabling an audit trail.

## External anchors

Reaching `AnchorThreshold` persists a `PendingAnchor` in the **same** transaction as the business row and audit entries. It does not claim that email was sent. Run this after commits, for example in a hosted background job using a fresh context:

```csharp
var auditOptions = new TamperEvidentOptions
{
    HmacSecretKey = secretFromYourSecretManager,
    SmtpHost = smtpHost,
    SmtpUser = smtpUser,
    SmtpPassword = smtpPassword,
    AnchorEmailTo = externalMailbox
};
var sent = await new AnchorDispatcher(dbContext, auditOptions)
    .DispatchPendingAsync(cancellationToken: stoppingToken);
```

You can inject an `IAnchorPublisher` via `CustomAnchorPublisher` instead of SMTP. Implement its `AnchorDelivery` overload to receive the persistent `PendingAnchor.Id` and cancellation token; the legacy three-argument overload remains compatible. SMTP includes that ID in `X-Audit-Anchor-Id` and the body, and the public anchor hash in `X-Audit-Anchor-Hash`. The HMAC secret is never mailed.

Delivery errors leave anchors pending for retry. Delivery is at least once: SMTP may accept a message before saving its delivery marker fails, so the receiver must deduplicate by `(deployment/chain identity, AnchorDelivery.Id)` or, for a legacy publisher, by the table and hash. SMTP acceptance is not final mailbox delivery or independent retention. Run one dispatcher per database to preserve the observed queue order; multiple concurrent dispatchers are not coordinated. Keep the receiver and its retained messages outside the audited database's administrative boundary.

Monitor `PendingAnchors` where `DeliveredAtUtc == null`, oldest `CreatedAtUtc`, `AttemptCount` and `LastError`. The dispatcher records failure types and can emit structured attempt logs through `LoggerFactory`. Alert on queue age or repeated failures; it does not schedule itself. A queued hash alone does not protect against a full database rewrite, and writes below the threshold are unanchored until an anchor is created and independently retained.

SMTP requires TLS by default and has a configurable 30-second attempt timeout (`SmtpTimeoutSeconds`). `AllowUnencryptedLoopbackSmtp=true` is restricted to literal loopback IPs for a disposable local sink; DNS names and remote IPs are rejected. The test suite uses this explicit mode with a real TCP receiver and no external email account. TLS/authentication with a deployed mail service and that service's retention policy remain operational acceptance checks.

To verify, obtain hashes from that external receiver in **chain order** and pass them to `AuditVerifier.VerifyTableIntegrityAsync(tableName, externalHashes)`. The verifier does not alter the supplied list; missing, extra or out-of-order hashes fail verification. An empty audit history is **inconclusive**, and a missing or mismatched chain state or external anchor is a failure. A v1 chain is rejected by the v2 verifier until an explicit migration is designed and reviewed.

## Test and support status

```powershell
dotnet test --filter 'Category!=SqlServer'
$env:EFCORE_AUDIT_SQLSERVER='Server=.\SQLEXPRESS;Integrated Security=true;TrustServerCertificate=true'
dotnet test
```

The first command runs portable unit tests; the second additionally creates and deletes uniquely named `AuditIt_*` databases on your **test** SQL Server. It checks sync/async saves, failure rollback, `SaveChanges(false)` rejection, caller-owned transactions, concurrent writers, retry configuration, verification and anchor retries. Do not point this environment variable at production.

The local SMTP tests use actual loopback TCP/SMTP, including a closed port, dispatcher process restart, default-TLS rejection, and replay of a stable anchor ID after an injected database acknowledgement failure. They prove local transport/outbox behavior; they do not prove external mailbox delivery or production operation. Local evidence and exact acceptance mapping are in [LOCAL_VALIDATION.md](docs/LOCAL_VALIDATION.md).

| Target | Evidence / support |
| --- | --- |
| .NET 9 / EF Core 9.0.16 / SQL Server 2022 | Locally verified; GitHub CI configured for the same target but not yet run on the unpublished branch |
| PostgreSQL / MySQL | Experimental lock-query paths; no integration result claimed |
| EF Core 6–8 or 10 / .NET 10 | Not tested or advertised as supported by this package |

Before .NET 9's support window ends, move the library, example and test provider together to .NET 10/EF Core 10 on a separate branch; rerun the SQL, SMTP, hash-compatibility and package checks before changing this matrix. Do not silently rehash existing data during that upgrade.

SQL Server uses transaction-scoped `sp_getapplock` plus a chain-row update lock. PostgreSQL and MySQL have provider-specific row-lock queries but lack integration coverage here; treat them as experimental and validate their transaction and concurrent first-row behavior before use.

If SQL Server `EnableRetryOnFailure()` is enabled, a direct audited `SaveChanges` call fails because the interceptor starts a user transaction. Wrap the **whole save operation** in `Database.CreateExecutionStrategy().ExecuteAsync(...)` and create a fresh `DbContext` inside each attempt. The SQL Server integration test covers the direct-call failure and the wrapped success path, but does not inject an actual transient fault or prove commit-uncertainty recovery. Follow [EF Core's transaction and retry guidance](https://learn.microsoft.com/en-us/ef/core/miscellaneous/connection-resiliency#execution-strategies-and-transactions) before deploying a retry policy; a commit can succeed even if its acknowledgement is lost.

## Upgrade and threat-model notes

- **1.x → 2.0 preview is breaking.** v2 requires a base64 key, adds `PendingAnchors` and `LastTimestampTicks`, and changes hash inputs. Keep 1.x data and external anchors intact. Do not reset or delete a production audit chain to make it pass the v2 verifier.
- A person with the HMAC key can forge a chain; rotate exposed keys and investigate under a documented incident process. The old public default key must never be reused.
- External anchor delivery is a separate trust boundary and can fail. Retention, access control, backup, monitoring and independent verification remain operational responsibilities.
- Raw SQL, bulk updates, direct database writes and changes outside EF `SaveChanges` bypass interceptors. Route relevant writes through the audited context or design a database-level control.
- `AuditLogs` contains old and new values. Restrict reads and configure redaction before using it with sensitive records.

Contributions and reproducible issues are welcome. Licensed under [MIT](LICENSE).
