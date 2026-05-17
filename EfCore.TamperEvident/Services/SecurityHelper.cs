using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EfCore.TamperEvident.Configuration;

namespace EfCore.TamperEvident.Services
{
    public static class SecurityHelper
    { 
        public static string GetLockQuery(DatabaseProvider provider, string tableName)
        {
            return provider switch
            {
                DatabaseProvider.SqlServer => $"SELECT * FROM AuditChainStates WITH (UPDLOCK, ROWLOCK) WHERE TableName = '{tableName}'",
                DatabaseProvider.PostgreSql => $"SELECT * FROM \"AuditChainStates\" WHERE \"TableName\" = '{tableName}' FOR UPDATE",
                DatabaseProvider.MySql => $"SELECT * FROM AuditChainStates WHERE TableName = '{tableName}' FOR UPDATE",
                _ => throw new NotSupportedException("Unsupported database provider")
            };
        } 
        public static string SerializeDeterministic(object obj)
        {
            if (obj == null) return null;

            var dictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(JsonSerializer.Serialize(obj));
            var sortedDict = new SortedDictionary<string, object>(dictionary);
            return JsonSerializer.Serialize(sortedDict);
        } 
        public static string ComputeHash(string rawData)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                StringBuilder sb = new StringBuilder();
                foreach (byte b in bytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }
    }
}