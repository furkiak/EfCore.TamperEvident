# Security policy

This package handles integrity evidence, so please report suspected security defects privately through GitHub's **Report a vulnerability** feature for this repository when available. Include the affected version, a minimal reproduction, the database provider and whether the issue needs access to the HMAC key. Do not include real keys, customer data or production connection strings.

The unpublished 2.0 preview is tested with .NET 9, EF Core 9 and SQL Server 2022. PostgreSQL and MySQL integration, upgrades from 1.x, and production deployments have not been verified here. The published 1.0.1 package has different behavior and is not covered by the v2 verification claims.

External anchors and an application-held secret are required to detect some forms of database-history replacement. See the [threat model and upgrade notes](README.md#upgrade-and-threat-model-notes).
