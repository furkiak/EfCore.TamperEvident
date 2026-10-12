namespace EfCore.TamperEvident
{
    /// <summary>
    /// Adds context to every change saved inside the scope: the user it is attributed to, the reason for the change and
    /// any other metadata (a ticket number, a job id...). Scopes nest and flow with async calls; disposing a scope
    /// restores the previous one. The reason and the metadata are sealed into the hash of every audit entry.
    /// </summary>
    /// <example>
    /// <code>
    /// using (AuditScope.Begin("job:nightly-import"))
    /// {
    ///     await db.SaveChangesAsync();
    /// }
    ///
    /// using (AuditScope.WithReason("Customer asked to change the address (ticket #4711)"))
    /// using (AuditScope.WithMetadata("ticket", 4711))
    /// {
    ///     await db.SaveChangesAsync();
    /// }
    /// </code>
    /// </example>
    public static class AuditScope
    {
        /// <summary>The metadata key the reason is stored under.</summary>
        public const string ReasonKey = "reason";

        private static readonly AsyncLocal<Frame?> Current = new();

        private static readonly IReadOnlyDictionary<string, object?> Empty = new Dictionary<string, object?>(StringComparer.Ordinal);

        /// <summary>The user of the innermost active scope, or <c>null</c> when no scope sets one.</summary>
        public static string? CurrentUserId => Current.Value?.UserId;

        /// <summary>The reason of the innermost active scope, or <c>null</c> when no scope sets one.</summary>
        public static string? CurrentReason => Current.Value?.Metadata.TryGetValue(ReasonKey, out var reason) == true ? reason as string : null;

        /// <summary>The metadata of all active scopes (inner scopes override outer ones), including the reason.</summary>
        public static IReadOnlyDictionary<string, object?> CurrentMetadata => Current.Value?.Metadata ?? Empty;

        /// <summary>Attributes the changes saved inside the scope to <paramref name="userId"/>.</summary>
        /// <param name="userId">The user the changes are attributed to.</param>
        /// <returns>Dispose it to restore the previous scope.</returns>
        public static IDisposable Begin(string userId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(userId);
            return Push(userId, null);
        }

        /// <summary>Attributes the changes saved inside the scope to <paramref name="userId"/> and records why they are made.</summary>
        /// <param name="userId">The user the changes are attributed to.</param>
        /// <param name="reason">Why the changes are made; <c>null</c> keeps the reason of an outer scope.</param>
        /// <returns>Dispose it to restore the previous scope.</returns>
        public static IDisposable Begin(string userId, string? reason)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(userId);
            return Push(userId, reason is null ? null : new[] { KeyValuePair.Create(ReasonKey, (object?)reason) });
        }

        /// <summary>Records why the changes saved inside the scope are made. The user is left as it is.</summary>
        /// <param name="reason">The reason, for example a ticket reference or a free text justification.</param>
        /// <returns>Dispose it to restore the previous scope.</returns>
        public static IDisposable WithReason(string reason)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(reason);
            return Push(null, new[] { KeyValuePair.Create(ReasonKey, (object?)reason) });
        }

        /// <summary>Adds one metadata entry to the changes saved inside the scope.</summary>
        /// <param name="key">The name of the entry.</param>
        /// <param name="value">Its value: a string, a number, a date or any object that serializes to JSON.</param>
        /// <returns>Dispose it to restore the previous scope.</returns>
        public static IDisposable WithMetadata(string key, object? value)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(key);
            return Push(null, new[] { KeyValuePair.Create(key, value) });
        }

        /// <summary>Adds metadata entries to the changes saved inside the scope.</summary>
        /// <param name="metadata">The entries.</param>
        /// <returns>Dispose it to restore the previous scope.</returns>
        public static IDisposable WithMetadata(IEnumerable<KeyValuePair<string, object?>> metadata)
        {
            ArgumentNullException.ThrowIfNull(metadata);
            return Push(null, metadata);
        }

        private static Restorer Push(string? userId, IEnumerable<KeyValuePair<string, object?>>? metadata)
        {
            var previous = Current.Value;
            var merged = previous?.Metadata;
            if (metadata is not null)
            {
                var copy = new Dictionary<string, object?>(previous?.Metadata ?? Empty, StringComparer.Ordinal);
                foreach (var (key, value) in metadata)
                {
                    ArgumentException.ThrowIfNullOrWhiteSpace(key, nameof(metadata));
                    copy[key] = value;
                }

                merged = copy;
            }

            Current.Value = new Frame(userId ?? previous?.UserId, merged ?? Empty);
            return new Restorer(previous);
        }

        private sealed record Frame(string? UserId, IReadOnlyDictionary<string, object?> Metadata);

        private sealed class Restorer : IDisposable
        {
            private readonly Frame? _previous;
            private bool _disposed;

            public Restorer(Frame? previous) => _previous = previous;

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
