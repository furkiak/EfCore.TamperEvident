using BenchmarkDotNet.Running;

// dotnet run -c Release --project benchmarks/EfCore.TamperEvident.Benchmarks -- --filter '*'
BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
