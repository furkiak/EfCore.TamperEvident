# Local acceptance evidence — 27 September 2026

This document describes isolated local verification, not production operation or a public release. The predecessor was `8dfa5e9`; the source commit containing this document identifies the new SMTP/model-mapping revision. All database names are unique `AuditIt_*` or `AuditDemo_*` fixtures and are deleted by their owning test/sample. SMTP binds only to IPv4 loopback and uses reserved `.test` email addresses; it never forwards mail. Test keys are synthetic and the demo's random key is not printed.

Result: 29/29 Release tests passed, including 15 real SQL Server 2022 Express integration scenarios, with no skips. The runnable quick start also passed and deleted its disposable database. Logs are written to ignored `TestResults/`; a clean-source rerun should be used for the distributable package.

Mutation check: temporarily removing the explicit `AuditChainStates` mapping made `AuditModelsWorkWithoutAuditDbSetProperties` fail against real SQL Server with `Invalid object name 'AuditChainStates'`. The source was restored immediately. This establishes that the new regression actually detects the quick-start failure rather than only mirroring an already passing path.

## Reproduce

```powershell
$env:EFCORE_AUDIT_SQLSERVER='Server=.\SQLEXPRESS;Integrated Security=true;TrustServerCertificate=true;Encrypt=true'
dotnet test -c Release --logger 'trx;LogFileName=ef-local-final.trx' --results-directory TestResults
dotnet run --project samples/SqlServerDemo -c Release --no-build
dotnet pack EfCore.TamperEvident/EfCore.TamperEvident.csproj -c Release
```

The test connection must point to an isolated SQL Server with create/drop-database permissions. The loopback SMTP fixture uses an ephemeral TCP port, and the test-only dispatcher worker accepts only `AuditIt_*` database names. The worker obtains its fixture key/connection through child-process environment variables, not command-line arguments or logs. The portable tests can be run with `--filter 'Category!=SqlServer'`.

## Acceptance mapping

| Plan item | Meaningful checked path |
| --- | --- |
| EF-02 | `ExternalTransactionRemainsOpenAndRollbackRemovesBusinessAndAudit`, `EmptySaveDoesNotOpenOrLeakATransaction`, `CancellationDuringAuditRollsBackBusinessWrite`, audit-failure rollback and `SaveWithoutAcceptingChangesIsRejectedAndRolledBack` run against SQL Server. Empty/cancelled saves leave no transaction and a closed connection. `RetryingStrategyRequiresWholeSaveDelegate` checks the rejected direct retry-enabled call and fresh-context wrapped success. |
| EF-03 | `AuditRegistrationRejectsMissingWeakAndUniformKeysWithoutPrintingThem` exercises real registration; the exception does not include supplied key values. `KEY_LIFECYCLE.md` defines host secret-manager use, operational key IDs, preserved old-key verification and separate-chain rotation. No per-row rotation tool is claimed. |
| EF-05 | `SyncAndAsyncSavesProduceVerifiableChainAndDurableAnchor` mutates the saved actor and verification fails. `CompositeKeysAndSchemasHaveIndependentChains` writes two same-tenant/different-key sales rows plus a support row with the same table name; composite identities remain distinct and schema chains verify independently. |
| EF-07 | `RealSmtpFailureSurvivesProcessRestartAndDeliversStableIdentity` launches one dispatcher process while the local SMTP port is closed: SQL retains the same pending ID/hash, one attempt and an SMTP error. That process exits. After the real TCP sink starts, a second process delivers the persisted anchor, SQL records delivery/attempt two, and the received headers/body contain the original ID/hash but not the HMAC key. A later dispatch sends nothing. |
| EF-07 replay | `SmtpAcceptedButDatabaseAcknowledgementFailedReplaysTheSameAnchorId` uses real SMTP and SQL, injecting a one-time save failure after SMTP acceptance. A new context retries the pending row; two SMTP messages have one stable anchor ID. Each attempt increments the counter once. This establishes why the receiver must deduplicate; it does not claim exactly-once delivery. |
| EF-08 | Six simultaneous first writers produce six SQL business/audit rows and a valid unbranched chain. Nested key ordering and the tr-TR/en-US decimal/date fixture give identical deterministic strings/UTF-8 data. Schema/composite tests also exercise multiple tables. Actual transient faults and PostgreSQL/MySQL remain wider acceptance work. |
| EF-09 local | New NuGet and symbols retain the 2.0 preview designation and include README, MIT license, architecture and the linked validation/key documents. The 1.0.1 history is unchanged. EF Core references are pinned to 9.0.16, support copy is limited to locally verified targets, and CI targets the same tests. The unpublished GitHub CI run is still an external gate. |
| Quick start | `AuditModelsWorkWithoutAuditDbSetProperties` reproduces the README's minimal context against SQL Server. The fixed model maps `AuditLogs`, `AuditChainStates` and `PendingAnchors` explicitly instead of relying on DbSet naming conventions. The runnable demo writes/verifies one customer and removes its fixture database. |

## Deliberate limits

Default SMTP TLS rejects a sink that does not offer STARTTLS. Plaintext SMTP is opt-in and restricted to literal loopback IPs. Deployed TLS/authentication, independent mailbox retention, a scheduler/alerts and a coordinated multi-dispatcher design are outside these isolated transport tests. Run one dispatcher per database. Pending age, attempts and error type are queryable; an unsent anchor cannot protect a database-wide rewrite, and below-threshold writes have a delayed anchoring window.

No actual network transient/uncertain commit, PostgreSQL/MySQL, 1.x in-place migration, per-row key rotation, GitHub CI or public NuGet release is claimed here. Those limitations do not erase the narrower SQL/SMTP/format checks above.
