# Changelog

## 2.0.0-preview.1 — unreleased

This preview changes the audit format and database schema. It must not be installed over a 1.x audit history without a reviewed migration.

- Audit both synchronous and asynchronous EF Core saves, including cancellation and rollback behavior.
- Keep a caller-owned transaction open after successful saves; roll it back if audit generation fails.
- Use a versioned, length-framed HMAC payload covering audit identity, actor and composite primary key.
- Require application-supplied base64 key material and reject empty, short or uniform keys.
- Add nested deterministic JSON serialization and default redaction for common secret fields.
- Persist external anchors in a transactional outbox; retry via `AnchorDispatcher`.
- Fail closed on missing audit history, missing chain state and unmatched external anchors.
- Add SQL Server integration tests for concurrency, rollback, cancellation and delivery failure.
- Correct the package's README, metadata, claims and support limits.

## 1.0.1 — published baseline

The original package is retained as a historical release. Its hashes, key format and database model are incompatible with this preview. Preserve 1.x audit rows and externally retained anchors.
