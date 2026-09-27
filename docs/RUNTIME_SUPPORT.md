# Runtime and provider support

The unpublished 2.0.0-preview.2 package contains two assemblies and dependency groups:

| Asset | Required EF packages | Serviced runtime used locally |
| --- | --- | --- |
| net9.0 | Microsoft.EntityFrameworkCore and Relational 9.0.20 | .NET 9.0.20 |
| net10.0 | Microsoft.EntityFrameworkCore and Relational 10.0.12 | .NET 10.0.12 |

A stable .NET 10 SDK builds both. Tests and the SQL Server sample select the same EF version as the library. CI has independent jobs for each target. `dotnet run` and EF tooling for a multi-target project need an explicit `--framework` selection. Do not mix different Microsoft EF package versions. A net10 consumer now selects the EF10 asset rather than falling back to a net9/EF9 assembly; its application-level EF changes and migrations require review.

Both targets use the same v2 production hash framing, interceptor and explicit audit model mapping. Fixed UTF-8/HMAC vectors, including Unicode and null/empty distinction, run on both. Actual SQL Server verifies a stored fixed-v2 row and detects its changed payload. These checks do not certify arbitrary database migrations, 1.x hash conversion, per-row key rotation or .NET 10 with EF Core 9. Existing 1.x rows and anchors must remain preserved for a separately reviewed migration.

As checked on 27 September 2026, [Microsoft's .NET policy](https://dotnet.microsoft.com/en-us/platform/support/policy) lists .NET 9 in maintenance through 10 November 2026, and .NET 10 LTS through 14 November 2028. A runtime must stay on serviced patches. [EF10 release documentation](https://learn.microsoft.com/en-us/ef/core/what-is-new/ef-core-10.0/whatsnew) requires .NET 10 and describes its own support window; this preview is not a Microsoft-supported product. The [EF10 breaking-change list](https://learn.microsoft.com/en-us/ef/core/what-is-new/ef-core-10.0/breaking-changes) must also be reviewed for each consuming application. SQL Server 2022 Express is the local integration provider; Azure SQL/SQL Server 2025 JSON behavior and PostgreSQL/MySQL are outside that result.

Versions were checked against Microsoft's [EF9.0.20](https://www.nuget.org/packages/Microsoft.EntityFrameworkCore/9.0.20) and [EF10.0.12](https://www.nuget.org/packages/Microsoft.EntityFrameworkCore/10.0.12) NuGet records. A direct and transitive known-vulnerability audit is required for the library, tests and sample. `Directory.Build.props` enables the audit, makes NU1901–NU1904 errors and treats other build warnings as errors; it does not suppress SDK or package warnings. System.Text.Json is supplied by the serviced framework/dependency graph, so its redundant explicit reference was removed.

SQL fixtures and loopback SMTP use synthetic data. Serviced test-runtime extraction is local to an owned test directory, not a machine-wide SDK/runtime update. The package is unsigned and unpublished; remote CI, clean-machine consumption, other providers and production SMTP/independent anchor retention remain release gates.
