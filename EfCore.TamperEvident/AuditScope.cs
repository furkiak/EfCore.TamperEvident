namespace EfCore.TamperEvident
{
    /// <summary>
    /// Attributes every change saved inside the scope to a given user. Handy for background jobs, imports and
    /// migrations where no HTTP user exists. The scope flows with async calls.
    /// </summary>
    /// <example>
    /// <code>
    /// using (AuditScope.Begin("job:nightly-import"))
    /// {
    ///     await db.SaveChangesAsync();
    /// }
    /// </code>
    /// </example>
    public static class AuditScope
    {
        private static readonly AsyncLocal<string?> Current = new();

        /// <summary>The user of the innermost active scope, or <c>null</c> when no scope is active.</summary>
        public static string? CurrentUserId => Current.Value;

        /// <summary>Starts a scope. Dispose the returned object to restore the previous scope.</summary>
        /// <param name="userId">The user the changes are attributed to.</param>
        public static IDisposable Begin(string userId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(userId);
            var previous = Current.Value;
            Current.Value = userId;
            return new Restorer(previous);
        }

        private sealed class Restorer : IDisposable
        {
            private readonly string? _previous;
            private bool _disposed;

            public Restorer(string? previous) => _previous = previous;

            public void Dispose()
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                Current.Value = _previous;
            }
        }
    }
}
