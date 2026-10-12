using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using EfCore.TamperEvident.Diagnostics;

namespace EfCore.TamperEvident.Tests
{
    /// <summary>Traces and metrics for OpenTelemetry.</summary>
    public sealed class TelemetryTests : IDisposable
    {
        private readonly ConcurrentBag<Activity> _activities = new();
        private readonly ConcurrentDictionary<string, long> _measurements = new();
        private readonly ActivityListener _activityListener;
        private readonly MeterListener _meterListener;
        private const string MarkerTable = "SystemLogs";

        public TelemetryTests()
        {
            _activityListener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == TamperEvidentTelemetry.SourceName,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStopped = _activities.Add
            };
            ActivitySource.AddActivityListener(_activityListener);

            _meterListener = new MeterListener
            {
                InstrumentPublished = (instrument, listener) =>
                {
                    if (instrument.Meter.Name == TamperEvidentTelemetry.SourceName)
                    {
                        listener.EnableMeasurementEvents(instrument);
                    }
                }
            };
            _meterListener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
                _measurements.AddOrUpdate(Key(instrument.Name, tags), value, (_, sum) => sum + value));
            _meterListener.SetMeasurementEventCallback<double>((instrument, _, tags, _) =>
                _measurements.AddOrUpdate(Key(instrument.Name, tags), 1, (_, count) => count + 1));
            _meterListener.Start();
        }

        // Other tests run in parallel. SystemLogs is excluded from the audit trail everywhere except in this class,
        // so only measurements tagged with it are attributed to these tests.
        private static string Key(string instrument, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            foreach (var tag in tags)
            {
                if (tag.Key == TamperEvidentTelemetry.Tags.Table && tag.Value is MarkerTable)
                {
                    return instrument;
                }
            }

            return "other:" + instrument;
        }

        [Fact]
        public async Task SealingAndVerifying_ProduceTracesAndMetrics()
        {
            using var harness = new Harness(o => o.ExcludedTables.Clear());

            await using (var db = harness.CreateContext())
            {
                db.SystemLogs.Add(new SystemLog { Message = "a" });
                db.SystemLogs.Add(new SystemLog { Message = "b" });
                await db.SaveChangesAsync();
            }

            await using (var db = harness.CreateContext())
            {
                var result = await harness.CreateVerifier(db).VerifyTableIntegrityAsync("SystemLogs");
                Assert.True(result.IsValid, result.Message);
            }

            var seal = Assert.Single(_activities, a => a.OperationName == TamperEvidentTelemetry.Activities.Seal
                && Equals(a.GetTagItem(TamperEvidentTelemetry.Tags.Table), MarkerTable));
            Assert.Equal(2, seal.GetTagItem(TamperEvidentTelemetry.Tags.Entries));
            Assert.Equal(ActivityStatusCode.Unset, seal.Status);

            var verify = Assert.Single(_activities, a => a.OperationName == TamperEvidentTelemetry.Activities.Verify
                && Equals(a.GetTagItem(TamperEvidentTelemetry.Tags.Table), "SystemLogs")
                && Equals(a.GetTagItem(TamperEvidentTelemetry.Tags.Entries), 2L));
            Assert.Equal("valid", verify.GetTagItem(TamperEvidentTelemetry.Tags.Result));
            Assert.Equal(false, verify.GetTagItem(TamperEvidentTelemetry.Tags.Incremental));

            _meterListener.RecordObservableInstruments();
            Assert.Equal(2, _measurements["tamper_evident.entries.sealed"]);
            Assert.Equal(1, _measurements["tamper_evident.verifications"]);
            Assert.Equal(2, _measurements["tamper_evident.entries.verified"]);
            Assert.Equal(1, _measurements["tamper_evident.verification.duration"]);
            Assert.True(_measurements.ContainsKey("other:tamper_evident.seal.duration"));
        }

        [Fact]
        public async Task AFailedVerification_IsMarkedAsAnError()
        {
            using var harness = new Harness();
            await using (var db = harness.CreateContext())
            {
                db.Documents.Add(new Document { Title = "x" });
                await db.SaveChangesAsync();
            }

            harness.Execute("UPDATE AuditLogs SET UserId = 'mallory'");
            await using (var db = harness.CreateContext())
            {
                Assert.False((await harness.CreateVerifier(db).VerifyTableIntegrityAsync("Documents")).IsValid);
            }

            Assert.Contains(_activities, a => a.OperationName == TamperEvidentTelemetry.Activities.Verify
                && a.Status == ActivityStatusCode.Error
                && Equals(a.GetTagItem(TamperEvidentTelemetry.Tags.Result), "DataManipulated"));
        }

        public void Dispose()
        {
            _activityListener.Dispose();
            _meterListener.Dispose();
        }
    }
}
