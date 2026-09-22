using System;
using System.Linq;

namespace EfCore.TamperEvident.Tests;

public static class TestKeys
{
    public static string Key => Convert.ToBase64String(Enumerable.Range(1, 32).Select(x => (byte)x).ToArray());
    public static string Other => Convert.ToBase64String(Enumerable.Range(33, 32).Select(x => (byte)x).ToArray());
}
