using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;

namespace EfCore.TamperEvident.Tests;

public sealed class AuditV2CompatibilityTests
{
    // Generated independently with Python hmac/hashlib, not the production helper.
    [Theory]
    [InlineData(null, "v2:0bc17f9fc5c539db35b73e99ca3f4a662c81bdcb0a92c838ed96443d9d00549f")]
    [InlineData("", "v2:4cd7c99a9f2164641b72809bd2c88df93e1f0cbe54c28b0eac0599b374df4189")]
    public void FixedV2FrameRemainsCompatibleAcrossTargets(string? oldValues, string expected)
    {
        Assert.Equal(expected, SecurityHelper.ComputeAuditHash(CreateLog(oldValues, expected), TestKeys.Key));
    }

    internal static AuditLog CreateLog(string? oldValues, string currentHash) => new()
    {
        Id = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"),
        PreviousHash = "GENESIS", TableName = "sales.Ölçüm", RecordId = "{\"Id\":7}",
        ActionType = "Added", OldValues = oldValues,
        NewValues = "{\"Name\":\"İstanbul\",\"Value\":1234.56}", UserId = "operator-42",
        TimestampTicks = 638000000000000000, CurrentHash = currentHash
    };
}
