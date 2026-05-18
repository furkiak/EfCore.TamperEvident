using System.Collections.Generic;
using EfCore.TamperEvident.Services;
using Xunit;

namespace EfCore.TamperEvident.Tests
{
    public class SecurityHelperTests
    {
        [Fact]
        public void ComputeHash_WithSameDataAndKey_ReturnsSameHash()
        {
            // Arrange
            string data = "TestPayload";
            string key = "MySecretKey123";

            // Act
            string hash1 = SecurityHelper.ComputeHash(data, key);
            string hash2 = SecurityHelper.ComputeHash(data, key);

            // Assert
            Assert.Equal(hash1, hash2);
            Assert.NotEmpty(hash1);
        }

        [Fact]
        public void ComputeHash_WithDifferentKey_ReturnsDifferentHash()
        {
            // Arrange
            string data = "TestPayload";
            string key1 = "MySecretKey123";
            string key2 = "DifferentKey456";

            // Act
            string hash1 = SecurityHelper.ComputeHash(data, key1);
            string hash2 = SecurityHelper.ComputeHash(data, key2);

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void SerializeDeterministic_SortsKeysConsistently()
        {
            // Arrange
            var dict1 = new Dictionary<string, object>
            {
                { "Z_Key", "Value1" },
                { "A_Key", 42 }
            };

            var dict2 = new Dictionary<string, object>
            {
                { "A_Key", 42 },
                { "Z_Key", "Value1" }
            };

            // Act
            var json1 = SecurityHelper.SerializeDeterministic(dict1);
            var json2 = SecurityHelper.SerializeDeterministic(dict2);

            // Assert
            Assert.Equal(json1, json2);
            Assert.Contains("\"A_Key\":42", json1);
            Assert.Contains("\"Z_Key\":\"Value1\"", json1);
        }
    }
}
