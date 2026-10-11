# Security policy

`EfCore.TamperEvident` exists to make tampering with audit data detectable, so reports about weaknesses are taken seriously.

## Supported versions

| Version | Supported |
|---|---|
| 2.x | ✅ security fixes |
| 1.x | ❌ please upgrade: 1.x has known weaknesses that 2.0 fixes (see the [changelog](CHANGELOG.md)) |

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.
Use GitHub's private reporting: **Security → Report a vulnerability** on the repository
(<https://github.com/furkiak/EfCore.TamperEvident/security/advisories/new>).

Helpful details: the affected version, the database provider, a minimal reproduction, and what an attacker would gain
(for example "an entry can be modified without the verifier noticing").

You can expect an acknowledgement within a few days and a fix or a mitigation plan as soon as the report is confirmed.

## What is in scope

- Ways to modify, remove, insert or reorder audit entries, or to forge the chain head, without verification failing
  (assuming the HMAC secret is not known to the attacker).
- Ways to redact values, or to fake a redaction, without a sealed `Redacted` entry and without verification failing;
  ways to recover a redacted value from its digest.
- Ways to make an evidence bundle verify although its content was changed, or to make an incremental verification
  accept entries that a full verification would reject (other than changes to entries before a trusted checkpoint).
- Flaws in the hashing, the canonical encoding, the webhook signatures or the key handling (including the command line tool).
- Vulnerabilities in the dashboard (authentication bypass, injection, information disclosure).

## What is out of scope (by design)

- An attacker who knows the HMAC secret *and* controls where the anchors are stored.
- Redactions made through the redaction API by someone allowed to call it: they are recorded in the chain, by design.
- Changes to the content of entries before the checkpoint of an incremental verification: full verifications find them.
- Changes made with `ExecuteUpdate`, `ExecuteDelete`, raw SQL or outside of EF Core: they are not audited. See
  [Security model and limitations](README.md#security-model-and-limitations).
