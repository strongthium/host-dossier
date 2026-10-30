using System.Net;
using System.Text;

namespace Strongthium.HostDossier.Tests;

/// <summary>What reads the DNS, against a server with exactly the records each test needs.</summary>
public class DnsCheckTests
{
    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    private static Task<SpfReport> Spf(FakeDns dns, string domain = "example.com") =>
        new SpfCheck(new Resolver([dns.Address])).CheckAsync(domain, Cancel);

    private static SpfNetwork Network(SpfReport report, string network) => Assert.Single(report.Networks, n => n.Network == network);

    // ---- SPF --------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Includes_are_followed_to_the_networks_at_the_bottom()
    {
        using var dns = new FakeDns()
            .Text("example.com", "some-verification=abc")
            .Text("example.com", "v=spf1 ip4:192.0.2.1 include:_spf.example.net -all")
            .Text("_spf.example.net", "v=spf1 include:_a.example.net ip6:2001:db8::/48 ~all")
            .Text("_a.example.net", "v=spf1 ip4:198.51.100.0/24 ip4:203.0.113.7/32 -all");

        var report = await Spf(dns);

        Assert.Equal("v=spf1 ip4:192.0.2.1 include:_spf.example.net -all", report.Record);
        Assert.Equal(["192.0.2.1", "198.51.100.0/24", "203.0.113.7", "2001:db8::/48"], report.Networks.Select(n => n.Network).OrderBy(n => n.Contains(':')).ThenBy(n => n, StringComparer.Ordinal));
        Assert.All(report.Networks, n => Assert.True(n.Allowed));
        Assert.Equal(2, report.DnsLookups);
        Assert.Equal("-all", report.AllTerm); // The inner records' "all" only ends those records.
        Assert.Contains("include:_a.example.net", Network(report, "198.51.100.0/24").Source);
        Assert.Equal(256, Network(report, "198.51.100.0/24").AddressCount);
        Assert.Contains(report.Findings, f => f.Level == Level.Good && f.Text.Contains("-all"));
    }

    [Fact]
    public async Task What_is_not_a_pass_is_listed_but_not_allowed()
    {
        using var dns = new FakeDns()
            .Text("example.com", "v=spf1 -ip4:192.0.2.1 ~ip4:192.0.2.2 ?ip4:192.0.2.3 +ip4:192.0.2.4 ~include:_soft.example.net include:_mixed.example.net -all")
            .Text("_soft.example.net", "v=spf1 ip4:198.51.100.1 -all")
            .Text("_mixed.example.net", "v=spf1 -ip4:198.51.100.2 ip4:198.51.100.3 -all");

        var report = await Spf(dns);

        Assert.False(Network(report, "192.0.2.1").Allowed);
        Assert.False(Network(report, "192.0.2.2").Allowed);
        Assert.False(Network(report, "192.0.2.3").Allowed);
        Assert.True(Network(report, "192.0.2.4").Allowed);
        Assert.False(Network(report, "198.51.100.1").Allowed); // ~include: its pass is only a soft fail here.
        Assert.False(Network(report, "198.51.100.2").Allowed);
        Assert.True(Network(report, "198.51.100.3").Allowed);
    }

    [Fact]
    public async Task A_and_mx_come_to_their_addresses_with_their_lengths()
    {
        using var dns = new FakeDns()
            .Text("example.com", "v=spf1 a mx a:web.example.net/28 mx:example.net/24//64 -all")
            .Address4("example.com", "192.0.2.10")
            .Address6("example.com", "2001:db8:1::10")
            .Mail("example.com", 10, "mail.example.com")
            .Address4("mail.example.com", "192.0.2.25")
            .Address4("web.example.net", "198.51.100.17")
            .Mail("example.net", 10, "mx.example.net")
            .Address4("mx.example.net", "203.0.113.25")
            .Address6("mx.example.net", "2001:db8:2::25");

        var report = await Spf(dns);

        Assert.True(Network(report, "192.0.2.10").Allowed);
        Assert.True(Network(report, "2001:db8:1::10").Allowed);
        Assert.Contains("mail.example.com", Network(report, "192.0.2.25").Source);
        Assert.True(Network(report, "198.51.100.16/28").Allowed);
        Assert.True(Network(report, "203.0.113.0/24").Allowed);
        Assert.True(Network(report, "2001:db8:2::/64").Allowed);
        Assert.Equal(4, report.DnsLookups);
    }

    [Fact]
    public async Task A_redirect_takes_over_only_without_an_all()
    {
        using var taken = new FakeDns()
            .Text("example.com", "v=spf1 ip4:192.0.2.1 redirect=_spf.example.net")
            .Text("_spf.example.net", "v=spf1 ip4:198.51.100.1 -all");
        var report = await Spf(taken);
        Assert.True(Network(report, "198.51.100.1").Allowed);
        Assert.Equal("-all", report.AllTerm); // The redirected record's "all" is the record's.
        Assert.Equal(1, report.DnsLookups);

        using var ignored = new FakeDns()
            .Text("example.com", "v=spf1 ip4:192.0.2.1 ~all redirect=_spf.example.net")
            .Text("_spf.example.net", "v=spf1 ip4:198.51.100.1 -all");
        report = await Spf(ignored);
        Assert.DoesNotContain(report.Networks, n => n.Network == "198.51.100.1");
        Assert.Equal("~all", report.AllTerm);
    }

    [Fact]
    public async Task What_comes_after_all_is_ignored()
    {
        using var dns = new FakeDns().Text("example.com", "v=spf1 -all ip4:192.0.2.1");
        var report = await Spf(dns);
        Assert.Empty(report.Networks);
    }

    [Fact]
    public async Task Macros_from_the_domain_are_filled_in_and_those_from_the_sender_are_reported()
    {
        using var dns = new FakeDns()
            .Text("example.com", "v=spf1 include:_spf.%{d} include:%{i}._ip.example.net exists:%{i}._x.example.net -all")
            .Text("_spf.example.com", "v=spf1 ip4:192.0.2.1 -all");
        var report = await Spf(dns);
        Assert.True(Network(report, "192.0.2.1").Allowed);
        Assert.True(report.Incomplete);
        Assert.Contains(report.Findings, f => f.Text.Contains("particular sender"));
        Assert.Equal(3, report.DnsLookups);
    }

    [Fact]
    public async Task A_loop_ends_and_is_reported()
    {
        using var dns = new FakeDns()
            .Text("example.com", "v=spf1 include:_a.example.net -all")
            .Text("_a.example.net", "v=spf1 include:example.com -all");
        var report = await Spf(dns);
        Assert.Contains(report.Findings, f => f.Level == Level.Bad && f.Text.Contains("includes itself"));
    }

    [Fact]
    public async Task More_than_ten_lookups_is_a_problem_but_all_are_still_shown()
    {
        var dns = new FakeDns();
        using (dns)
        {
            var includes = string.Join(' ', Enumerable.Range(1, 12).Select(i => $"include:_{i}.example.net"));
            dns.Text("example.com", $"v=spf1 {includes} -all");
            for (var i = 1; i <= 12; i++) dns.Text($"_{i}.example.net", $"v=spf1 ip4:192.0.2.{i} -all");
            var report = await Spf(dns);
            Assert.Equal(12, report.DnsLookups);
            Assert.Equal(12, report.Networks.Count);
            Assert.Contains(report.Findings, f => f.Level == Level.Bad && f.Text.Contains("limit is 10"));
        }
    }

    [Theory]
    [InlineData("v=spf1 +all", Level.Bad, "anyone in the world")]
    [InlineData("v=spf1 all", Level.Bad, "anyone in the world")]
    [InlineData("v=spf1 ?all", Level.Warning, "neutral")]
    [InlineData("v=spf1 ~all", Level.Notice, "suspect")]
    [InlineData("v=spf1 ip4:192.0.2.1", Level.Warning, "doesn't end")]
    [InlineData("v=spf1 ip4:not-an-address -all", Level.Bad, "isn't a valid network")]
    [InlineData("v=spf1 bogus:example.net -all", Level.Bad, "isn't an SPF mechanism")]
    [InlineData("v=spf1 ip4:10.0.0.0/8 -all", Level.Warning, "directly allows")]
    public async Task Bad_records_are_called_what_they_are(string record, Level level, string text)
    {
        using var dns = new FakeDns().Text("example.com", record);
        var report = await Spf(dns);
        Assert.Contains(report.Findings, f => f.Level == level && f.Text.Contains(text));
    }

    [Fact]
    public async Task Two_records_or_none_are_problems()
    {
        using var two = new FakeDns().Text("example.com", "v=spf1 -all").Text("example.com", "v=spf1 ~all");
        Assert.Contains((await Spf(two)).Findings, f => f.Level == Level.Bad && f.Text.Contains("2 SPF records"));

        using var none = new FakeDns().Text("example.com", "something=else");
        var report = await Spf(none);
        Assert.Null(report.Record);
        Assert.Contains(report.Findings, f => f.Text.Contains("no SPF record"));
    }

    [Fact]
    public async Task An_include_with_no_record_is_a_problem()
    {
        using var dns = new FakeDns().Text("example.com", "v=spf1 include:gone.example.net -all");
        var report = await Spf(dns);
        Assert.Contains(report.Findings, f => f.Level == Level.Bad && f.Text.Contains("gone.example.net"));
    }

    [Fact]
    public async Task A_long_record_in_several_strings_is_one_record()
    {
        var networks = string.Join(' ', Enumerable.Range(1, 40).Select(i => $"ip4:192.0.2.{i}"));
        using var dns = new FakeDns().Text("example.com", $"v=spf1 {networks} -all");
        var report = await Spf(dns);
        Assert.Equal(40, report.Networks.Count);
    }

    // ---- DMARC, DKIM, BIMI --------------------------------------------------------------------------------------------

    [Fact]
    public async Task A_subdomain_falls_back_on_the_domain_for_dmarc()
    {
        using var dns = new FakeDns().Text("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com");
        var report = await new DmarcCheck(new Resolver([dns.Address])).CheckAsync("mail.example.com", Cancel);
        Assert.Equal("_dmarc.example.com", report.RecordAt);
        Assert.Equal("reject", report.Policy);
        Assert.True(report.Enforcing);
    }

    [Fact]
    public async Task Dmarc_reports_to_another_domain_need_its_agreement()
    {
        using var refused = new FakeDns().Text("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:d@example.net");
        var report = await new DmarcCheck(new Resolver([refused.Address])).CheckAsync("example.com", Cancel);
        Assert.Contains(report.Findings, f => f.Text.Contains("hasn't published"));
        Assert.False(report.Enforcing);

        using var agreed = new FakeDns()
            .Text("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:d@example.net")
            .Text("example.com._report._dmarc.example.net", "v=DMARC1");
        report = await new DmarcCheck(new Resolver([agreed.Address])).CheckAsync("example.com", Cancel);
        Assert.DoesNotContain(report.Findings, f => f.Text.Contains("hasn't published"));
    }

    [Fact]
    public async Task Partial_dmarc_is_not_enforcing()
    {
        using var dns = new FakeDns().Text("_dmarc.example.com", "v=DMARC1; p=quarantine; pct=50; sp=none");
        var report = await new DmarcCheck(new Resolver([dns.Address])).CheckAsync("example.com", Cancel);
        Assert.False(report.Enforcing);
        Assert.Contains(report.Findings, f => f.Text.Contains("50%"));
        Assert.Contains(report.Findings, f => f.Text.Contains("Subdomains"));
    }

    [Fact]
    public async Task Dkim_finds_the_selectors_that_have_keys()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(1024);
        using var dns = new FakeDns()
            .Text("_domainkey.example.com", "o=-")
            .Text("s1._domainkey.example.com", "v=DKIM1; k=rsa; p=" + Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()))
            .Text("www._domainkey.example.com", "not a key");
        var report = await new DkimCheck(new Resolver([dns.Address])).CheckAsync("example.com", ["s1", "s2", "www"], Cancel);
        var key = Assert.Single(report.Keys);
        Assert.Equal("s1", key.Selector);
        Assert.Equal(1024, key.Bits);
        Assert.Equal("some", report.DomainKeyNode);
        Assert.Contains(report.Findings, f => f.Level == Level.Notice && f.Text.Contains("1024"));
    }

    [Fact]
    public async Task No_domainkey_node_suggests_no_dkim_at_all()
    {
        using var dns = new FakeDns().Text("example.com", "unrelated");
        var report = await new DkimCheck(new Resolver([dns.Address])).CheckAsync("example.com", ["s1"], Cancel);
        Assert.Empty(report.Keys);
        Assert.Equal("none", report.DomainKeyNode);
    }

    [Fact]
    public async Task Bimi_without_an_enforcing_dmarc_is_a_problem_and_no_record_is_not()
    {
        using var none = new FakeDns().Text("example.com", "unrelated");
        using var http = new HttpClient(new NoNetwork());
        var report = await new BimiCheck(new Resolver([none.Address]), http).CheckAsync("example.com", null, Cancel);
        Assert.Null(report.Record);
        Assert.Empty(report.Findings);

        using var declined = new FakeDns().Text("default._bimi.example.com", "v=BIMI1; l=; a=");
        report = await new BimiCheck(new Resolver([declined.Address]), http).CheckAsync("mail.example.com", new DmarcReport { Domain = "example.com", Policy = "none" }, Cancel);
        Assert.Equal("default._bimi.example.com", report.RecordAt);
        Assert.Contains(report.Findings, f => f.Level == Level.Bad && f.Text.Contains("DMARC"));
        Assert.Contains(report.Findings, f => f.Text.Contains("declines"));
    }

    [Fact]
    public async Task Logo_addresses_must_be_https()
    {
        using var dns = new FakeDns().Text("default._bimi.example.com", "v=BIMI1; l=http://example.com/logo.svg");
        using var http = new HttpClient(new NoNetwork());
        var report = await new BimiCheck(new Resolver([dns.Address]), http).CheckAsync("example.com", new DmarcReport { Domain = "example.com", Policy = "reject" }, Cancel);
        Assert.Contains(report.Findings, f => f.Text.Contains("isn't on an https address"));
    }

    // ---- Blocklists ---------------------------------------------------------------------------------------------------

    private static BlocklistEntry List(string zone) => new() { Zone = zone, Name = zone };

    /// <summary>A list that behaves as RFC 5782 says: its test address is listed, and the other test address never is.</summary>
    private static FakeDns ProperList(FakeDns dns, string zone) => dns.Address4($"2.0.0.127.{zone}", "127.0.0.2");

    [Fact]
    public async Task A_proper_list_is_believed_and_says_what_it_lists()
    {
        using var dns = ProperList(new FakeDns(), "bl.example.org")
            .Address4("1.2.0.192.bl.example.org", "127.0.0.2")
            .Text("1.2.0.192.bl.example.org", "Listed for sending spam");
        var check = new BlocklistCheck([new Resolver([dns.Address])]);
        var health = await check.HealthAsync([List("bl.example.org")], Cancel);
        Assert.True(health[0].Health.Usable);

        var listed = await check.CheckAsync("192.0.2.1", [List("bl.example.org")], Cancel);
        Assert.Equal(BlocklistStatus.Listed, listed[0].Status);
        Assert.Equal("127.0.0.2", listed[0].Codes);
        Assert.Equal("Listed for sending spam", listed[0].Reason);

        var clean = await check.CheckAsync("192.0.2.2", [List("bl.example.org")], Cancel);
        Assert.Equal(BlocklistStatus.Clean, clean[0].Status);
    }

    [Fact]
    public async Task A_list_that_says_everything_is_listed_is_left_out()
    {
        using var dns = new FakeDns().Address4("2.0.0.127.dead.example.org", "127.0.0.2").Address4("1.0.0.127.dead.example.org", "127.0.0.2");
        var health = await new BlocklistCheck([new Resolver([dns.Address])]).HealthAsync([List("dead.example.org")], Cancel);
        Assert.False(health[0].Health.Usable);
        Assert.Contains("everything is listed", health[0].Health.Detail);
    }

    [Fact]
    public async Task A_list_that_refuses_the_resolver_is_left_out_with_the_reason()
    {
        using var dns = new FakeDns().Address4("2.0.0.127.bl.example.org", "127.255.255.254");
        var health = await new BlocklistCheck([new Resolver([dns.Address])]).HealthAsync([List("bl.example.org")], Cancel);
        Assert.False(health[0].Health.Usable);
        Assert.Contains("public and shared", health[0].Health.Detail);
    }

    [Fact]
    public async Task A_list_without_its_test_address_is_left_out()
    {
        using var dns = new FakeDns();
        var health = await new BlocklistCheck([new Resolver([dns.Address])]).HealthAsync([List("gone.example.org")], Cancel);
        Assert.False(health[0].Health.Usable);
    }

    [Fact]
    public async Task A_list_is_asked_through_the_first_server_it_answers()
    {
        using var refuses = new FakeDns().Address4("2.0.0.127.bl.example.org", "127.255.255.254").Address4("1.2.0.192.bl.example.org", "127.255.255.254");
        using var answers = ProperList(new FakeDns(), "bl.example.org").Address4("1.2.0.192.bl.example.org", "127.0.0.2");
        var check = new BlocklistCheck([new Resolver([refuses.Address]), new Resolver([answers.Address])]);
        var health = await check.HealthAsync([List("bl.example.org")], Cancel);
        Assert.True(health[0].Health.Usable);
        var results = await check.CheckAsync("192.0.2.1", [List("bl.example.org")], Cancel);
        Assert.Equal(BlocklistStatus.Listed, results[0].Status);
    }

    [Fact]
    public async Task An_answer_outside_127_is_not_a_listing()
    {
        using var dns = ProperList(new FakeDns(), "bl.example.org").Address4("1.2.0.192.bl.example.org", "198.51.100.1");
        var results = await new BlocklistCheck([new Resolver([dns.Address])]).CheckAsync("192.0.2.1", [List("bl.example.org")], Cancel);
        Assert.Equal(BlocklistStatus.Failed, results[0].Status);
    }

    [Fact]
    public async Task A_policy_listing_is_marked_as_one()
    {
        using var dns = new FakeDns().Address4("1.2.0.192.zen.spamhaus.org", "127.0.0.11");
        var results = await new BlocklistCheck([new Resolver([dns.Address])]).CheckAsync("192.0.2.1", [List("zen.spamhaus.org")], Cancel);
        Assert.Equal(BlocklistStatus.Listed, results[0].Status);
        Assert.True(results[0].Policy);
        Assert.Contains("PBL", results[0].Reason);
    }

    [Fact]
    public async Task A_list_without_ipv6_is_not_asked_about_ipv6()
    {
        using var dns = new FakeDns();
        var results = await new BlocklistCheck([new Resolver([dns.Address])]).CheckAsync("2001:db8::1", [List("bl.example.org")], Cancel);
        Assert.Equal(BlocklistStatus.NotApplicable, results[0].Status);
    }

    // ---- The whole lookup, with Cloudflare ------------------------------------------------------------------------------

    /// <summary>Every step that would go out to the internet is off: what's left is Cloudflare's records, through the lookup.</summary>
    [Fact]
    public async Task A_cloudflare_zone_shows_the_real_addresses_and_what_gives_them_away()
    {
        using var dns = new FakeDns();
        var settings = new Settings
        {
            Registration = false, Dns = false, Tls = false, Ports = false, Web = false, Mail = false, Blocklists = false, FollowRelated = false,
            Resolvers = [dns.Address],
            CloudflareAccounts = [new CloudflareAccount { Name = "Test", Token = "secret-token" }],
        };
        var handler = new Answering(request =>
        {
            Assert.Equal("api.cloudflare.com", request.RequestUri!.Host);
            Assert.Equal("Bearer secret-token", request.Headers.Authorization?.ToString());
            return request.RequestUri.PathAndQuery.Contains("dns_records", StringComparison.Ordinal)
                ? """
                  { "success": true, "result_info": { "total_pages": 1 }, "result": [
                    { "name": "example.com", "type": "A", "content": "192.0.2.80", "proxied": true, "ttl": 1 },
                    { "name": "legacy.example.com", "type": "A", "content": "192.0.2.80", "proxied": false, "ttl": 300 },
                    { "name": "example.com", "type": "TXT", "content": "v=spf1 -all", "proxied": false, "ttl": 300 }
                  ] }
                  """
                : """{ "success": true, "result": [ { "id": "z1", "name": "example.com", "status": "active" } ] }""";
        });

        var target = Names.ParseTarget("www.example.com", out _)!;
        var dossier = Lookup.Begin(target);
        using (var lookup = new Lookup(settings, handler))
        {
            await lookup.RunAsync(dossier, Cancel);
        }

        var zone = Assert.Single(dossier.Cloudflare.Zones);
        Assert.Equal(3, zone.Records.Count);
        Assert.Contains(dossier.Addresses["192.0.2.80"].Roles, r => r.StartsWith("Real address of example.com", StringComparison.Ordinal));
        Assert.Contains(dossier.Dns.Subdomains, s => s.Name == "legacy.example.com" && s.Source == "Cloudflare");
        Assert.Contains(dossier.Cloudflare.Findings, f => f.Level == Level.Warning && f.Text.Contains("legacy.example.com") && f.Text.Contains("192.0.2.80"));
        Assert.DoesNotContain("secret-token", Export.ToJson(dossier));
        Assert.DoesNotContain("secret-token", Export.ToMarkdown(dossier));
        Assert.DoesNotContain(dossier.Steps, s => s.State == "failed");
    }

    private sealed class Answering(Func<HttpRequestMessage, string> answer) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(answer(request), Encoding.UTF8, "application/json") });
    }

    private sealed class NoNetwork : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("There's no network in the tests.");
    }
}
