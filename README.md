# EF Core Tamper-Evident Audit Trail

![NuGet Version](https://img.shields.io/badge/nuget-v1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![EF Core](https://img.shields.io/badge/EF_Core-6.0%20%7C%2010.0-purple)

Enterprise-grade **tamper-evident audit logging** for Entity Framework Core.

`EfCore.TamperEvident` provides a **zero-trust audit trail** mechanism using **cryptographic hash chaining** to make database manipulation detectable — even in scenarios where database administrators have full access to the database server.

Designed for systems requiring **compliance, forensic traceability, and high-integrity audit logging**.


<p align="center">
  <img src="https://github.com/furkiak/EfCore.TamperEvident/blob/main/image.jpg" width="600" title="Tamper Evident">
</p>


---

## ✨ Key Features

### 🔐 Cryptographic HMAC Hash Chain
Each audit record is cryptographically linked to the previous entry using **HMAC-SHA256 hashing** and a secure secret key, creating an immutable audit sequence.

Any modification, deletion, or insertion into historical records immediately breaks chain integrity.

---

### 🛡 SMTP Anchoring (Anti-DBA Tampering)
Protects against **database history rewriting attacks**.

The library periodically generates a **Root Hash (Anchor)** and sends it to an external secure email address. Even if a DBA recalculates hashes and rewrites history inside the database, integrity verification will fail when compared with externally stored anchors.

Furthermore, attackers cannot regenerate valid hashes without the Application's internal `HmacSecretKey`, completely preventing DBA-level forgery.

---

### ⚡ Concurrency-Safe Chain Generation
Prevents **chain forks** and race conditions in high-concurrency environments.

Uses native database row-level locking mechanisms:

| Database | Lock Strategy |
|----------|----------------|
| SQL Server | `UPDLOCK` |
| PostgreSQL | `FOR UPDATE` |
| MySQL | `FOR UPDATE` |

---

### 🔄 Two-Phase Commit Interception
Fully compatible with `IDENTITY` / auto-increment primary keys.

The interceptor safely captures entity states and generates audit logs **after primary keys are created**, ensuring referential accuracy.

---

### 📦 Deterministic JSON Serialization
Eliminates hash inconsistencies caused by unpredictable property ordering during JSON serialization.

Ensures **stable, repeatable cryptographic hashes** across environments.

**JSON Diff Profiling:** Only the `Modified` properties (changing from original to new value) are serialized into the audit logs, drastically reducing database storage bloat for large entities.

---

### 🗑 Intelligent Soft-Delete Detection
If you use logical deletions (`IsDeleted = true`), the library will automatically detect it and mark the row as `SoftDelete` instead of treating it as a standard data `Update`. This provides deeper insights into your evidence analytics.

---

## 📦 Installation

### Package Manager Console

```powershell
Install-Package EfCore.TamperEvident
```

### .NET CLI

```bash
dotnet add package EfCore.TamperEvident
```

---

## 🚀 Quick Start

### 1. Add Required Entities to Your DbContext

Add the required audit tables to your existing `DbContext`.

```csharp
using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

public class MyCrmDbContext : DbContext
{
    public MyCrmDbContext(
        DbContextOptions<MyCrmDbContext> options
    ) : base(options)
    {
    }

    // Required by EfCore.TamperEvident
    public DbSet<AuditLog> AuditLogs { get; set; }

    public DbSet<AuditChainState> AuditChainStates { get; set; }

    // Your application entities
    public DbSet<Customer> Customers { get; set; }
}
```

---

### 2. Configure in `Program.cs`

Enable tamper-evident auditing with a single extension method.

```csharp
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;

builder.Services.AddDbContext<MyCrmDbContext>(options =>
{
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"));

    options.UseTamperEvidentAudit(audit =>
    {
        audit.DbProvider = DatabaseProvider.SqlServer;

        // Track Insert / Update / Delete
        audit.TrackedOperations = AuditOperation.All;

        // Exclude specific tables
        audit.ExcludedTables = new List<string>
        {
            "SystemLogs",
            "TempData"
        };

        // SMTP Anchoring (Optional but Recommended)
        audit.AnchorThreshold = 500;

        audit.SmtpHost = "smtp.company.com";
        audit.SmtpPort = 587;
        audit.SmtpUser = "security-bot@company.com";
        audit.SmtpPassword = "your-secure-password";

        // Secret keys for cryptographic strength
        audit.HmacSecretKey = "Your_Very_Strong_App_Secret_Key_Here";
        audit.SoftDeleteColumnName = "IsDeleted"; // Customize soft-delete column

        audit.AnchorEmailTo =
            "compliance-officer@company.com";
    });
});
```

---

### 3. Start Using EF Core Normally

No business logic changes required.

The library automatically intercepts:

- `SaveChanges()`
- `SaveChangesAsync()`

and securely builds the audit chain in the background.

```csharp
_context.Customers.Add(new Customer
{
    Name = "John Doe",
    Company = "Acme Corp"
});

await _context.SaveChangesAsync();
```

Audit logs are generated automatically.

---

## 🔍 Verifying Audit Integrity

If tampering is suspected, use the `AuditVerifier` to validate audit integrity.

```csharp
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Services;

// Have your configured options with the Secret Key ready
var options = new TamperEvidentOptions 
{ 
    HmacSecretKey = "Your_Very_Strong_App_Secret_Key_Here" 
};

// Inject your DbContext and pass the options
var verifier = new AuditVerifier(_context, options);

// Optional:
// Anchor hashes received externally (email)
var providedAnchors = new List<string>
{
    "a1b2c3d4...",
    "f5e6d7c8..."
};

// Verify table integrity
var result =
    await verifier.VerifyTableIntegrityAsync(
        "Customers",
        providedAnchors);

if (result.IsValid)
{
    Console.WriteLine(result.Message);
    // Verification successful
}
else
{
    Console.WriteLine(
        $"SECURITY ALERT: {result.Message}");
}
```
 
---

## 🏗 Supported Databases

| Database | Supported |
|----------|------------|
| SQL Server | ✅ |
| PostgreSQL | ✅ |
| MySQL | ✅ |

---

## 🎯 Use Cases

`EfCore.TamperEvident` is particularly suitable for:

- Financial systems
- Healthcare applications
- ERP / CRM platforms
- Compliance-heavy environments
- Legal evidence retention
- High-security enterprise systems

---

## ⚠ Security Model

This library provides **tamper evidence**, not tamper prevention.

An attacker with sufficient privileges may still alter data, but **those modifications become cryptographically detectable**.

For maximum protection:

- Enable **SMTP Anchoring**
- Store anchor emails externally
- Restrict database administrative access
- Run scheduled integrity verification

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome.

Please open an issue before submitting large architectural changes.

---

## 📄 License

Licensed under the **MIT License**.
