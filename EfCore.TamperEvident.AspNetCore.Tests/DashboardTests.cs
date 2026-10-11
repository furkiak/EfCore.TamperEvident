using System.Net;
using System.Net.Http.Json;
using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;

namespace EfCore.TamperEvident.AspNetCore.Tests
{
    public class DashboardTests
    {
        private static HttpRequestMessage Post(string url, object? body = null, bool withHeader = true)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = JsonContent.Create(body ?? new { }) };
            if (withHeader)
            {
                request.Headers.Add("X-Requested-With", "tamper-evident");
            }

            return request;
        }

        private static async Task<JsonElement> ReadAsync(HttpResponseMessage response)
        {
            response.EnsureSuccessStatusCode();
            return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
        }

        // ---- who may see it ------------------------------------------------------------------------------------

        [Fact]
        public async Task Dashboard_RefusesToServe_InProduction_WhenItIsNotProtected()
        {
            await using var app = await TestApp.StartAsync("Production");

            var response = await app.Client.GetAsync("/audit");

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Contains("RequireAuthorization", await response.Content.ReadAsStringAsync());
            Assert.Equal(HttpStatusCode.Forbidden, (await app.Client.GetAsync("/audit/api/overview")).StatusCode);
        }

        [Fact]
        public async Task Dashboard_IsServed_InDevelopment_WithoutAuthorization()
        {
            await using var app = await TestApp.StartAsync("Development");
            Assert.Equal(HttpStatusCode.OK, (await app.Client.GetAsync("/audit")).StatusCode);
        }

        [Fact]
        public async Task Dashboard_IsServed_InProduction_WhenAnonymousAccessIsAcceptedExplicitly()
        {
            await using var app = await TestApp.StartAsync("Production", o => o.AllowAnonymous = true);
            Assert.Equal(HttpStatusCode.OK, (await app.Client.GetAsync("/audit")).StatusCode);
        }

        [Fact]
        public async Task Dashboard_EnforcesAuthorization_WhenItIsRequired()
        {
            await using var app = await TestApp.StartAsync("Production", configureGroup: g => g.RequireAuthorization());

            var anonymous = await app.Client.GetAsync("/audit/api/overview");
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

            var request = new HttpRequestMessage(HttpMethod.Get, "/audit/api/overview");
            request.Headers.Add("X-Test-User", "auditor");
            Assert.Equal(HttpStatusCode.OK, (await app.Client.SendAsync(request)).StatusCode);
        }

        // ---- the page -------------------------------------------------------------------------------------------

        [Fact]
        public async Task Index_SetsTheBaseAddress_AndStrictSecurityHeaders()
        {
            await using var app = await TestApp.StartAsync(configureDashboard: o => o.Title = "My <Audit> & Co");

            var response = await app.Client.GetAsync("/audit");
            var html = await response.Content.ReadAsStringAsync();

            Assert.Equal("text/html; charset=utf-8", response.Content.Headers.ContentType!.ToString());
            Assert.Contains("<base href=\"/audit/\">", html);
            Assert.Contains("<title>My &lt;Audit&gt; &amp; Co</title>", html);
            Assert.DoesNotContain("{{", html);

            var csp = response.Headers.GetValues("Content-Security-Policy").Single();
            Assert.Contains("script-src 'self'", csp);
            Assert.Contains("frame-ancestors 'none'", csp);
            Assert.DoesNotContain("unsafe-inline", csp);
            Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
            Assert.Equal("no-store", response.Headers.CacheControl!.ToString());
        }

        [Fact]
        public async Task Index_ContainsNoInlineScriptsOrStyles_SoTheStrictPolicyHolds()
        {
            await using var app = await TestApp.StartAsync();
            var html = await app.Client.GetStringAsync("/audit");

            Assert.DoesNotMatch("<script(?![^>]*\\bsrc=)", html);
            Assert.DoesNotContain("<style", html);
            Assert.DoesNotContain(" style=\"", html);
            Assert.DoesNotContain("onclick=", html);
        }

        [Theory]
        [InlineData("dashboard.css", "text/css")]
        [InlineData("dashboard.js", "text/javascript")]
        [InlineData("favicon.svg", "image/svg+xml")]
        public async Task Assets_AreServed_WithAnETag(string file, string contentType)
        {
            await using var app = await TestApp.StartAsync();

            var response = await app.Client.GetAsync("/audit/assets/" + file);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.StartsWith(contentType, response.Content.Headers.ContentType!.ToString());
            Assert.NotNull(response.Headers.ETag);
            Assert.True((await response.Content.ReadAsByteArrayAsync()).Length > 100);

            var conditional = new HttpRequestMessage(HttpMethod.Get, "/audit/assets/" + file);
            conditional.Headers.IfNoneMatch.Add(response.Headers.ETag);
            Assert.Equal(HttpStatusCode.NotModified, (await app.Client.SendAsync(conditional)).StatusCode);
        }

        [Theory]
        [InlineData("missing.js")]
        [InlineData("index.html")]
        [InlineData("..%2Fappsettings.json")]
        public async Task UnknownAssets_AreNotFound(string file)
        {
            await using var app = await TestApp.StartAsync();
            Assert.NotEqual(HttpStatusCode.OK, (await app.Client.GetAsync("/audit/assets/" + file)).StatusCode);
        }

        [Fact]
        public async Task TheStylesheet_NeverLoadsExternalResources()
        {
            await using var app = await TestApp.StartAsync();
            var css = await app.Client.GetStringAsync("/audit/assets/dashboard.css");
            var js = await app.Client.GetStringAsync("/audit/assets/dashboard.js");

            Assert.DoesNotContain("http://", css.Replace("http://www.w3.org/2000/svg", string.Empty));
            Assert.DoesNotContain("https://", css);
            Assert.DoesNotContain("@import", css);
            Assert.DoesNotContain("innerHTML", js);
            Assert.DoesNotContain("eval(", js);
        }

        // ---- the API --------------------------------------------------------------------------------------------

        [Fact]
        public async Task Overview_SummarisesTheAuditTrail()
        {
            await using var app = await TestApp.StartAsync(configureDashboard: o => o.Title = "Acme");
            await app.SeedAsync();

            var overview = await ReadAsync(await app.Client.GetAsync("/audit/api/overview"));

            Assert.Equal("Acme", overview.GetProperty("title").GetString());
            Assert.Equal(2, overview.GetProperty("totals").GetProperty("tables").GetInt32());
            Assert.Equal(5, overview.GetProperty("totals").GetProperty("records").GetInt32());
            Assert.Equal(2, overview.GetProperty("totals").GetProperty("users").GetInt32());

            var people = overview.GetProperty("tables").EnumerateArray().Single(t => t.GetProperty("table").GetString() == "People");
            Assert.Equal(4, people.GetProperty("records").GetInt32());
            Assert.Equal(4, people.GetProperty("lastSequence").GetInt64());
            Assert.True(people.GetProperty("headAuthenticated").GetBoolean());
            Assert.Equal(64, people.GetProperty("headHash").GetString()!.Length);

            Assert.True(overview.GetProperty("capabilities").GetProperty("verify").GetBoolean());
            Assert.True(overview.GetProperty("capabilities").GetProperty("export").GetBoolean());
            Assert.Equal(JsonValueKind.Null, overview.GetProperty("verification").ValueKind);
        }

        [Fact]
        public async Task Overview_OfAnEmptyDatabase_IsEmptyButValid()
        {
            await using var app = await TestApp.StartAsync();

            var overview = await ReadAsync(await app.Client.GetAsync("/audit/api/overview"));

            Assert.Equal(0, overview.GetProperty("totals").GetProperty("records").GetInt32());
            Assert.Equal(0, overview.GetProperty("tables").GetArrayLength());
        }

        [Fact]
        public async Task Logs_ArePagedAndNewestFirst()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();

            var page1 = await ReadAsync(await app.Client.GetAsync("/audit/api/logs?pageSize=2&page=1"));
            var page3 = await ReadAsync(await app.Client.GetAsync("/audit/api/logs?pageSize=2&page=3"));

            Assert.Equal(5, page1.GetProperty("total").GetInt32());
            Assert.Equal(2, page1.GetProperty("items").GetArrayLength());
            Assert.Equal(1, page3.GetProperty("items").GetArrayLength());
            Assert.Equal("Modified", page1.GetProperty("items")[0].GetProperty("action").GetString());
        }

        [Fact]
        public async Task Logs_AreFilteredByEveryCriterion()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();

            async Task<int> Count(string query) =>
                (await ReadAsync(await app.Client.GetAsync("/audit/api/logs?" + query))).GetProperty("total").GetInt32();

            Assert.Equal(4, await Count("table=People"));
            Assert.Equal(1, await Count("table=Pets"));
            Assert.Equal(2, await Count("table=People&recordId=1"));
            Assert.Equal(3, await Count("recordId=1"));
            Assert.Equal(1, await Count("action=Modified"));
            Assert.Equal(5, await Count("action=Added,Modified"));
            Assert.Equal(4, await Count("user=alice"));
            Assert.Equal(1, await Count("user=bob"));
            Assert.Equal(0, await Count("user=nobody"));
            Assert.Equal(5, await Count("from=2000-01-01&to=2999-01-01"));
            Assert.Equal(0, await Count("from=2999-01-01"));
            Assert.Equal(2, await Count("table=People&seqFrom=2&seqTo=3"));
            Assert.Equal(1, await Count("q=Pets"));
        }

        [Fact]
        public async Task Logs_FindAnEntryByAHashPrefix()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();
            var all = await ReadAsync(await app.Client.GetAsync("/audit/api/logs"));
            var hash = all.GetProperty("items")[2].GetProperty("currentHash").GetString()!;

            var found = await ReadAsync(await app.Client.GetAsync("/audit/api/logs?q=" + hash[..12]));

            Assert.Equal(1, found.GetProperty("total").GetInt32());
        }

        [Theory]
        [InlineData("pageSize=100000", 200)]
        [InlineData("pageSize=-5", 1)]
        [InlineData("pageSize=abc", 50)]
        public async Task Logs_ClampTheirPageSize(string query, int expected)
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();

            var data = await ReadAsync(await app.Client.GetAsync("/audit/api/logs?" + query));
            Assert.Equal(expected, data.GetProperty("pageSize").GetInt32());
        }

        [Fact]
        public async Task Logs_AreSafeAgainstInjection()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();

            var response = await app.Client.GetAsync("/audit/api/logs?table=" + Uri.EscapeDataString("People'; DROP TABLE AuditLogs;--") + "&q=%25_%25");
            var data = await ReadAsync(response);

            Assert.Equal(0, data.GetProperty("total").GetInt32());
            Assert.Equal(5, (await ReadAsync(await app.Client.GetAsync("/audit/api/logs"))).GetProperty("total").GetInt32());
        }

        [Fact]
        public async Task Activity_CountsEntriesPerDayAndAction()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();

            var activity = await ReadAsync(await app.Client.GetAsync("/audit/api/activity?days=3"));
            var series = activity.GetProperty("series").EnumerateArray().ToList();

            Assert.Equal(3, series.Count);
            var today = series[^1];
            Assert.Equal(DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), today.GetProperty("date").GetString());
            Assert.Equal(4, today.GetProperty("added").GetInt32());
            Assert.Equal(1, today.GetProperty("modified").GetInt32());
            Assert.Equal(0, series[0].GetProperty("added").GetInt32());
        }

        // ---- verification ---------------------------------------------------------------------------------------

        [Fact]
        public async Task Verify_RequiresTheAntiForgeryHeader()
        {
            await using var app = await TestApp.StartAsync();

            var response = await app.Client.SendAsync(Post("/audit/api/verify", withHeader: false));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        [Fact]
        public async Task Verify_ReportsAnIntactTrail_AndRemembersIt()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();

            var report = await ReadAsync(await app.Client.SendAsync(Post("/audit/api/verify")));

            Assert.True(report.GetProperty("isValid").GetBoolean());
            Assert.Equal(5, report.GetProperty("recordsChecked").GetInt64());
            Assert.Equal(2, report.GetProperty("tables").GetArrayLength());
            Assert.Equal("manual", report.GetProperty("source").GetString());

            var overview = await ReadAsync(await app.Client.GetAsync("/audit/api/overview"));
            Assert.True(overview.GetProperty("verification").GetProperty("isValid").GetBoolean());
        }

        [Fact]
        public async Task Verify_DetectsTampering_AndNamesTheEntry()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();
            await app.ExecuteAsync("UPDATE AuditLogs SET UserId = 'mallory' WHERE TableName = 'People' AND SequenceNumber = 2");

            var report = await ReadAsync(await app.Client.SendAsync(Post("/audit/api/verify")));

            Assert.False(report.GetProperty("isValid").GetBoolean());
            var people = report.GetProperty("tables").EnumerateArray().Single(t => t.GetProperty("table").GetString() == "People");
            Assert.Equal("DataManipulated", people.GetProperty("failure").GetString());
            Assert.Equal(2, people.GetProperty("failedSequence").GetInt64());
            var pets = report.GetProperty("tables").EnumerateArray().Single(t => t.GetProperty("table").GetString() == "Pets");
            Assert.True(pets.GetProperty("isValid").GetBoolean());
        }

        [Fact]
        public async Task Verify_OneTable_OnlyChecksThatTable()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();

            var report = await ReadAsync(await app.Client.SendAsync(Post("/audit/api/verify", new { table = "Pets" })));

            Assert.Single(report.GetProperty("tables").EnumerateArray());
            Assert.Equal(1, report.GetProperty("recordsChecked").GetInt64());
        }

        [Fact]
        public async Task Verify_MatchesPastedAnchorEmails_WithoutKnowingTheirTable()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();
            var logs = await ReadAsync(await app.Client.GetAsync("/audit/api/logs?table=People"));
            var hash = logs.GetProperty("items")[3].GetProperty("currentHash").GetString()!;

            var email = $"Subject: SECURITY ANCHOR - People Table\n\nTable: People\nSequence: 1\n\nAnchor Hash Key:\n{hash}\n\nPlease do not delete this email.";
            var report = await ReadAsync(await app.Client.SendAsync(Post("/audit/api/verify", new { anchors = email })));

            Assert.True(report.GetProperty("isValid").GetBoolean());
            var matched = report.GetProperty("tables").EnumerateArray().Sum(t => t.GetProperty("anchorsMatched").GetInt32());
            Assert.Equal(1, matched);
        }

        [Fact]
        public async Task Verify_FlagsPastedAnchorsThatOccurNowhere()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();

            var report = await ReadAsync(await app.Client.SendAsync(Post("/audit/api/verify", new { anchors = new string('a', 64) })));

            Assert.False(report.GetProperty("isValid").GetBoolean());
            var last = report.GetProperty("tables").EnumerateArray().Last();
            Assert.Equal("AnchorMismatch", last.GetProperty("failure").GetString());
            Assert.Equal(JsonValueKind.Null, last.GetProperty("table").ValueKind);
        }

        [Fact]
        public async Task Verify_UsesTheConfiguredStoredAnchors()
        {
            string? seenHash = null;
            await using var app = await TestApp.StartAsync(configureDashboard: o => o.AnchorProvider = (_, _) =>
                Task.FromResult<IReadOnlyDictionary<string, IEnumerable<string>>?>(new Dictionary<string, IEnumerable<string>>
                {
                    ["People"] = new[] { seenHash ?? new string('b', 64) }
                }));
            await app.SeedAsync();

            var report = await ReadAsync(await app.Client.SendAsync(Post("/audit/api/verify")));

            Assert.False(report.GetProperty("isValid").GetBoolean());
            var people = report.GetProperty("tables").EnumerateArray().Single(t => t.GetProperty("table").GetString() == "People");
            Assert.Equal("AnchorMismatch", people.GetProperty("failure").GetString());
        }

        [Fact]
        public async Task Verify_IsNotImplemented_WithoutASecretKey()
        {
            await using var app = await TestApp.StartAsync(registerAuditOptions: false);

            var response = await app.Client.SendAsync(Post("/audit/api/verify"));
            Assert.Equal(HttpStatusCode.NotImplemented, response.StatusCode);

            var overview = await ReadAsync(await app.Client.GetAsync("/audit/api/overview"));
            Assert.False(overview.GetProperty("capabilities").GetProperty("verify").GetBoolean());
        }

        [Fact]
        public async Task Verify_CanUseOptionsPassedToTheDashboardDirectly()
        {
            await using var app = await TestApp.StartAsync(
                registerAuditOptions: false,
                configureDashboard: o => o.AuditOptions = new EfCore.TamperEvident.Configuration.TamperEvidentOptions { HmacSecretKey = TestApp.Key });
            await app.SeedAsync();

            var report = await ReadAsync(await app.Client.SendAsync(Post("/audit/api/verify")));
            Assert.True(report.GetProperty("isValid").GetBoolean());
        }

        // ---- export ---------------------------------------------------------------------------------------------

        [Fact]
        public async Task Export_Csv_IsADownload()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();

            var response = await app.Client.GetAsync("/audit/api/export?format=csv&table=People");
            var csv = await response.Content.ReadAsStringAsync();

            Assert.Equal("text/csv", response.Content.Headers.ContentType!.MediaType);
            Assert.Matches("^tamper-evident-People-\\d{8}-\\d{6}\\.csv$", response.Content.Headers.ContentDisposition!.FileName!.Trim('"'));
            Assert.Equal(5, csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length);
        }

        [Fact]
        public async Task Export_JsonLines_AndEvidenceBundle()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();

            var lines = (await app.Client.GetStringAsync("/audit/api/export?format=jsonl")).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(5, lines.Length);

            var bundle = await ReadAsync(await app.Client.GetAsync("/audit/api/export?format=evidence"));
            Assert.Equal(2, bundle.GetProperty("tables").GetArrayLength());
            Assert.True(bundle.GetProperty("tables")[0].GetProperty("verification").GetProperty("isValid").GetBoolean());
        }

        [Fact]
        public async Task Export_SanitisesTheFileName_AndRejectsUnknownFormats()
        {
            await using var app = await TestApp.StartAsync();
            await app.SeedAsync();

            var response = await app.Client.GetAsync("/audit/api/export?format=csv&table=" + Uri.EscapeDataString("../..\\evil\r\nX: y"));
            var name = response.Content.Headers.ContentDisposition!.FileName!;
            Assert.DoesNotContain("/", name);
            Assert.DoesNotContain("\\", name);
            Assert.DoesNotContain("\n", name);

            Assert.Equal(HttpStatusCode.BadRequest, (await app.Client.GetAsync("/audit/api/export?format=exe")).StatusCode);
        }

        [Fact]
        public async Task Export_CanBeDisabled()
        {
            await using var app = await TestApp.StartAsync(configureDashboard: o => o.AllowExport = false);

            Assert.Equal(HttpStatusCode.NotFound, (await app.Client.GetAsync("/audit/api/export?format=csv")).StatusCode);
            var overview = await ReadAsync(await app.Client.GetAsync("/audit/api/overview"));
            Assert.False(overview.GetProperty("capabilities").GetProperty("export").GetBoolean());
        }

        [Fact]
        public async Task ApiResponses_AreNeverCached()
        {
            await using var app = await TestApp.StartAsync();
            var response = await app.Client.GetAsync("/audit/api/overview");
            Assert.Equal("no-store", response.Headers.CacheControl!.ToString());
        }

        [Theory]
        [InlineData("/audit", "/audit/")]
        [InlineData("/admin/audit/", "/admin/audit/")]
        [InlineData("tamper", "/tamper/")]
        public async Task TheDashboard_CanBeMountedAtAnyPath(string pattern, string expectedBase)
        {
            // The base href must follow the pattern, otherwise the relative asset URLs break.
            await using var app = await TestApp.StartAsync(pattern: pattern);

            var html = await app.Client.GetStringAsync(expectedBase);

            Assert.Contains($"<base href=\"{expectedBase}\">", html);
            Assert.Equal(HttpStatusCode.OK, (await app.Client.GetAsync(expectedBase + "assets/dashboard.css")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await app.Client.GetAsync(expectedBase + "api/overview")).StatusCode);
        }
    }
}
