# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-10-11

2.0 is a **major** release: it fixes several serious defects of 1.x, which required a schema change and a few API changes.
See [Upgrading from 1.x](README.md#upgrading-from-1x).

### Security

- **The user is now part of the sealed record.** Previously `UserId` was not covered by the hash, so the author of a change could be rewritten undetected.
- **Hash inputs are length-prefixed** (canonical format, `HashVersion = 2`). With plain string concatenation, characters could be moved between neighbouring fields without breaking the hash.
- **Deleting the newest entries is detected.** The head of every chain (`AuditChainStates`) is authenticated with an HMAC and compared with the newest entry during verification; entries behind the head are reported too.
- **The public default HMAC key was removed.** `HmacSecretKey` is required (16+ characters, 32+ recommended) and is validated at registration time.
- Entries now carry a **sequence number**; the order no longer depends on clocks, which could produce false alarms with several application servers.
- A unique index on `(TableName, PreviousHash)` makes a forked chain impossible, even if locking were bypassed.
- Hash comparisons run in constant time.

### Added

- `EfCore.TamperEvident.AspNetCore` package: the **Liquid Glass dashboard** (`MapTamperEvidentDashboard`), scheduled verification (`AddTamperEvidentVerification`), a health check, and HTTP user attribution (`UseHttpContextUser`).
- Support for the synchronous `SaveChanges()`, `TransactionScope`, and `EnableRetryOnFailure` execution strategies.
- .NET 8, .NET 9 and .NET 10 targets with EF Core 8, 9 and 10.
- Automatic database provider detection; SQLite and the in-memory provider; table, column and schema names read from the model (snake_case, custom schemas).
- `ApplyTamperEvidentAudit()` model configuration and index definitions on the audit tables.
- User attribution: `UserIdProvider`, `DefaultUserId`, `AuditScope`.
- `[AuditIgnore]`, `[AuditMask]`, `ExcludedProperties`, `MaskedProperties`.
- Key rotation: `HmacKeyId`, `AdditionalHmacKeys`.
- `AuditVerificationResult` / `AuditVerificationReport` with a failure kind, the failing sequence and timings; `VerifyAllAsync`; verification that is consistent while the application writes.
- Anchor publishers: `WebhookAnchorPublisher`, `FileAnchorPublisher`, `CompositeAnchorPublisher`; retries with back-off; delivery only after the transaction committed; `AnchorSources` and `FlushAnchorsAsync`.
- `AuditActions.Restored` detection and `DeletedAt`-style soft deletes.
- `AuditExporter` (CSV, JSON Lines, evidence bundle) and composable audit queries (`AuditLogs()`, `ForTable`, `ByUser`, `GetAuditHistoryAsync`...).
- `AddTamperEvident` / `AddTamperEvidentVerifier` dependency injection extensions and typed `UseTamperEvidentAudit` overloads.
- Provider conformance tests (PostgreSQL, MySQL/MariaDB, SQL Server) and a runnable `samples/QuickStart`.
- `README.tr.md` (Turkish), `SECURITY.md`, release and CI workflows.

### Fixed

- `SaveChanges()` (synchronous) was **never audited**.
- Saving only excluded tables left a transaction open, so **the data was never committed**.
- The interceptor **committed transactions that belonged to the caller** (the ownership check was always true).
- `EnableRetryOnFailure` made every save fail.
- The nested `SaveChanges` that wrote the audit entries is replaced by parameterized SQL, which also removes stale chain-state tracking problems.
- A cancelled or failed save could leak a transaction.
- `SaveChanges(acceptAllChangesOnSuccess: false)` inserted the audited entities a second time.
- Entity graphs with navigation cycles crashed the serializer; entities without a parameterless constructor could not be audited. Only mapped properties are read now.
- JSON key order depended on the current culture (`tr-TR` produced a different order than `en-US`), which could change hashes between machines.
- Inserts were captured before the database generated keys (`"Id":0`); they now record the generated values.
- Anchor e-mails always reported `0` new records and could contain a hash that was newer than the anchored position; anchors were sent before the audited transaction committed.
- `VerifyTableIntegrityAsync` removed items from the list the caller passed in.
- The `AuditChainStates` and `AuditLogs` table names were hard-coded in the lock SQL, which broke custom names, schemas and naming conventions.
- The first write to a table could fail when several writers started at once (and deadlocked on InnoDB).
- `ExcludedTables` was case-sensitive.
- `GeneratePackageOnBuild` produced a package on every build; local publish profiles and a personal path were committed.

### Changed

- `AuditLog` gained `SequenceNumber`, `HashVersion` and `KeyId`; `AuditChainState` gained `LastSequence`, `KeyId` and `Mac`. Column lengths are now bounded and indexes are defined. **A migration is required.**
- `AuditVerifier.VerifyTableIntegrityAsync` returns an `AuditVerificationResult` (it still deconstructs into `(bool, string)`) and accepts any `IEnumerable<string>` of anchors plus a `CancellationToken`.
- `IAnchorPublisher` has a new `PublishAsync(AuditAnchor)` member; implementations of the old `SendAnchorAsync` keep working through default interface members.
- `SoftDeleteColumnName` matching is case-insensitive.
- Hashing uses the one-shot `HMACSHA256.HashData` API; the interceptor is thread-safe and can be shared as a singleton.

### Removed

- `DbProvider` no longer needs to be set (the property stays as an optional override).
- `SecurityHelper.GetLockQuery` (the lock statements are generated from the model now).
- The default `HmacSecretKey`.
- `System.Text.Json` as an explicit package dependency.

### Compatibility

- Entries written by 1.x remain verifiable (`HashVersion = 0`) and the chain continues behind them. If you never configured a key, add `TamperEvidentOptions.Version1DefaultKey` to `AdditionalHmacKeys` to verify them.

## [1.0.1]

- Resolved the N+1 query issue and removed compiler warnings.

## [1.0.0]

- Initial release: HMAC hash chain, SMTP anchoring, row-level locking, deterministic JSON, soft delete detection.
