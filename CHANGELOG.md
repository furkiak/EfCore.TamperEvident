# Changelog

## 2.0.0-preview.1 — unreleased

This preview changes the audit format and database schema. It must not be installed over a 1.x audit history without a reviewed migration.

- Audit both synchronous and asynchronous EF Core saves, including cancellation and rollback behavior.
- Keep a caller-owned transaction open after successful saves; roll it back if audit generation fails.
- Reject audited `SaveChanges(false)` calls and roll back instead of writing business entries twice.
- Use a versioned, length-framed HMAC payload covering audit identity, actor and composite primary key.
- Require application-supplied base64 key material and reject empty, short or uniform keys.
- Add nested deterministic JSON serialization and default redaction for common secret fields.
- Persist external anchors in a transactional outbox; retry via `AnchorDispatcher`.
- Deliver a stable outbox ID through an optional compatible publisher overload and SMTP headers; log pending failures and count each delivery attempt once.
- Keep SMTP TLS enabled by default, bound send attempts and restrict plaintext test SMTP to literal loopback IPs.
- Verify real local SMTP refusal, restart/retry and acknowledgement-failure replay against SQL Server.
- Add a runnable disposable SQL Server quick start and an explicit historical-key verification/rotation plan.
- Map all three internal audit tables explicitly so contexts without audit DbSet properties work as documented.
- Fail closed on missing audit history, missing chain state and unmatched external anchors.
- Add SQL Server integration tests for concurrency, rollback, cancellation, delivery failure and retry configuration.
- Correct the package's README, metadata, claims and support limits.

## 1.0.1 — published baseline

The original package is retained as a historical release. Its hashes, key format and database model are incompatible with this preview. Preserve 1.x audit rows and externally retained anchors.
