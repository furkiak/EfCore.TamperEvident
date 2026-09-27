# Local acceptance evidence — 27 September 2026

This document describes isolated local verification, not production operation or a public release. `f92ffbf` is the historical .NET 9/EF9.0.16, 29-test SMTP/model-mapping baseline; the source commit containing this document identifies the dual-target preview. All database names are unique `AuditIt_*` or `AuditDemo_*` fixtures and are deleted by their owning test/sample. SMTP binds only to IPv4 loopback and uses reserved `.test` email addresses; it never forwards mail. Test keys are synthetic and the demo's random key is not printed.

Result: 32/32 Release tests passed on .NET 9.0.20/EF9.0.20 and 32/32 on .NET 10.0.12/EF10.0.12, including 16 real SQL Server 2022 Express cases per target, with no skips. These are 64 executions of 32 cases, not 64 distinct cases. Two independent Python HMAC/UTF-8 vectors pin Unicode byte framing and null/empty separation. A new SQL case loads the fixed v2 chain with a trusted synthetic anchor, verifies it, changes null to empty and observes verification failure. This is fixed-format compatibility coverage, not a 1.x or arbitrary application migration.

The .NET 9 tests and their dispatcher children use an owned .NET 9.0.20 runtime extracted from Microsoft's official ZIP after its release-manifest SHA-512 matched; machine-wide .NET installs were not changed. The SDK is 10.0.401. The v2 production hash/interceptor/model code is unchanged. Logs are written to ignored `TestResults/`; a clean-source rerun should be used for the distributable package.

Historical mapping mutation: temporarily removing the explicit `AuditChainStates` mapping made `AuditModelsWorkWithoutAuditDbSetProperties` fail against real SQL Server with `Invalid object name 'AuditChainStates'` on f92ffbf's predecessor. The source was restored. Current dual-target validation reruns this production call path; the historical mutation remains labelled rather than represented as a new mutation.

## Reproduce

```powershell
$env:EFCORE_AUDIT_SQLSERVER='Server=.\SQLEXPRESS;Integrated Security=true;TrustServerCertificate=true;Encrypt=true'
dotnet test -c Release --framework net9.0 --logger 'trx;LogFileName=ef-net9-final.trx' --results-directory TestResults
dotnet test -c Release --framework net10.0 --logger 'trx;LogFileName=ef-net10-final.trx' --results-directory TestResults
dotnet run --project samples/SqlServerDemo -c Release --framework net9.0 --no-build
dotnet run --project samples/SqlServerDemo -c Release --framework net10.0 --no-build
dotnet pack EfCore.TamperEvident/EfCore.TamperEvident.csproj -c Release
```

The test connection must point to an isolated SQL Server with create/drop-database permissions. Both serviced runtime versions must be available. For an isolated .NET 9 host, set `EFCORE_AUDIT_TEST_DOTNET_HOST` to its absolute dotnet path and append `-- RunConfiguration.DotNetHostPath=<same path>` to its test command; the option is only for test workers, not application key management. The loopback SMTP fixture uses an ephemeral TCP port, and the dispatcher worker accepts only `AuditIt_*` database names. It obtains the fixture key/connection through child-process environment variables, not command-line arguments or logs. Portable tests can be run with `--filter 'Category!=SqlServer'`.

## Acceptance mapping

| Plan item | Meaningful checked path |
| --- | --- |
| EF-02 | `ExternalTransactionRemainsOpenAndRollbackRemovesBusinessAndAudit`, `EmptySaveDoesNotOpenOrLeakATransaction`, `CancellationDuringAuditRollsBackBusinessWrite`, audit-failure rollback and `SaveWithoutAcceptingChangesIsRejectedAndRolledBack` run against SQL Server. Empty/cancelled saves leave no transaction and a closed connection. `RetryingStrategyRequiresWholeSaveDelegate` checks the rejected direct retry-enabled call and fresh-context wrapped success. |
| EF-03 | `AuditRegistrationRejectsMissingWeakAndUniformKeysWithoutPrintingThem` exercises real registration; the exception does not include supplied key values. `KEY_LIFECYCLE.md` defines host secret-manager use, operational key IDs, preserved old-key verification and separate-chain rotation. No per-row rotation tool is claimed. |
| EF-05 | `SyncAndAsyncSavesProduceVerifiableChainAndDurableAnchor` mutates the saved actor and verification fails. `CompositeKeysAndSchemasHaveIndependentChains` writes two same-tenant/different-key sales rows plus a support row with the same table name; composite identities remain distinct and schema chains verify independently. |
| EF-07 | `RealSmtpFailureSurvivesProcessRestartAndDeliversStableIdentity` launches one dispatcher process while the local SMTP port is closed: SQL retains the same pending ID/hash, one attempt and an SMTP error. That process exits. After the real TCP sink starts, a second process delivers the persisted anchor, SQL records delivery/attempt two, and the received headers/body contain the original ID/hash but not the HMAC key. A later dispatch sends nothing. |
| EF-07 replay | `SmtpAcceptedButDatabaseAcknowledgementFailedReplaysTheSameAnchorId` uses real SMTP and SQL, injecting a one-time save failure after SMTP acceptance. A new context retries the pending row; two SMTP messages have one stable anchor ID. Each attempt increments the counter once. This establishes why the receiver must deduplicate; it does not claim exactly-once delivery. |
| EF-08 | Six simultaneous first writers produce six SQL business/audit rows and a valid unbranched chain. Nested key ordering and the tr-TR/en-US decimal/date fixture give identical deterministic strings/UTF-8 data. Schema/composite tests also exercise multiple tables. Actual transient faults and PostgreSQL/MySQL remain wider acceptance work. |
| EF-09 local | NuGet and symbols retain the 2.0 preview designation and include README, MIT license, architecture and validation/key/runtime documents. The 1.0.1 history is unchanged. Separate net9/EF9.0.20 and net10/EF10.0.12 assets are configured; SQL/SMTP/fixed-v2 coverage is per target. The unpublished GitHub CI run is still an external gate. |
| Quick start | `AuditModelsWorkWithoutAuditDbSetProperties` reproduces the README's minimal context against SQL Server. The fixed model maps `AuditLogs`, `AuditChainStates` and `PendingAnchors` explicitly instead of relying on DbSet naming conventions. The runnable demo writes/verifies one customer and removes its fixture database. |

## Deliberate limits

Default SMTP TLS rejects a sink that does not offer STARTTLS. Plaintext SMTP is opt-in and restricted to literal loopback IPs. Deployed TLS/authentication, independent mailbox retention, a scheduler/alerts and a coordinated multi-dispatcher design are outside these isolated transport tests. Run one dispatcher per database. Pending age, attempts and error type are queryable; an unsent anchor cannot protect a database-wide rewrite, and below-threshold writes have a delayed anchoring window.

No actual network transient/uncertain commit, PostgreSQL/MySQL, 1.x in-place migration, per-row key rotation, GitHub CI or public NuGet release is claimed here. Those limitations do not erase the narrower SQL/SMTP/format checks above.
