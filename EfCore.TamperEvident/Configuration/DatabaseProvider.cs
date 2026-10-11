namespace EfCore.TamperEvident.Configuration
{
    /// <summary>
    /// The database providers the chain head locking is implemented for.
    /// </summary>
    public enum DatabaseProvider
    {
        /// <summary>Microsoft SQL Server (<c>UPDLOCK</c>).</summary>
        SqlServer = 0,

        /// <summary>PostgreSQL (<c>FOR UPDATE</c>).</summary>
        PostgreSql = 1,

        /// <summary>MySQL / MariaDB (<c>FOR UPDATE</c>).</summary>
        MySql = 2,

        /// <summary>SQLite (the database is write-locked by the transaction itself).</summary>
        Sqlite = 3,

        /// <summary>The EF Core in-memory provider (meant for unit tests only, no transactions or locks).</summary>
        InMemory = 4,

        /// <summary>Detect the provider from the configured <c>DbContext</c> (the default).</summary>
        Auto = 100
    }
}
