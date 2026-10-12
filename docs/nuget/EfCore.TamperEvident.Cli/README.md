# tamper-evident

A .NET tool for auditors: verifies [EfCore.TamperEvident](https://www.nuget.org/packages/EfCore.TamperEvident) evidence
bundles **offline, without access to the database**. Every hash, link, redaction, signed chain head and anchor is checked
again with the secret key.

```bash
dotnet tool install -g EfCore.TamperEvident.Cli
```

## Usage

```bash
export TAMPER_EVIDENT_KEY='…'                                   # the secret is never accepted on the command line

tamper-evident verify evidence.json                             # verify a bundle
tamper-evident verify evidence.json --anchors anchors.jsonl     # ...and check it against anchors stored elsewhere
tamper-evident verify evidence.json --key-file /run/secrets/audit-key --json
tamper-evident inspect evidence.json                            # summarize a bundle without verifying it
tamper-evident keygen                                           # print a new random secret key
```

| Option | |
|---|---|
| `--key-env <VARIABLE>` | Read the secret from an environment variable (default `TAMPER_EVIDENT_KEY`). |
| `--key-file <PATH>` / `--key-stdin` | Read the secret from a file, or from the first line of standard input. |
| `--key-id <ID>` | The key id of the secret, when key rotation is used. |
| `--retired-key <ID>=env:<VAR>` | A retired key that older entries were sealed with (repeatable; also `file:<PATH>`). |
| `--anchors <FILE>` | Anchors received outside of the database (repeatable): a `FileAnchorPublisher` file, or any text that contains the hashes, such as saved anchor e-mails. |
| `--json` | Machine-readable output. |

**Exit codes:** `0` intact · `1` tampering detected · `2` invalid input. Bundles are read as a stream, so their size is not
limited by memory.

Bundles are written by `AuditExporter.WriteEvidenceBundleAsync` or the export page of the dashboard. See the
[documentation](https://github.com/furkiak/EfCore.TamperEvident#evidence-bundles-and-the-command-line-tool).
