using System.Text.Json;

namespace Strongthium.HostDossier.Tests;

/// <summary>Reports read back from JSON, the cache, and SPF's addresses through the whole lookup.</summary>
public class ReportTests
{
    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    // ---- Reading a report back -------------------------------------------------------------------------------------------

    [Fact]
    public void A_report_read_back_is_the_same_report()
    {
        var original = SampleData.Build();
        var json = Export.ToJson(original);
        var read = Export.FromJson(json);

        Assert.Equal(json, Export.ToJson(read));
        Assert.Equal(Export.ToMarkdown(original), Export.ToMarkdown(read));
        Assert.Equal(original.Addresses.Count, read.Addresses.Count);
        Assert.Equal(original.Mail!.Spf!.Networks.Count, read.Mail!.Spf!.Networks.Count);
        Assert.Equal("Example Mail Relay", read.Mail.Spf.Networks[1].Routes[0].Provider);
        Assert.Equal(original.Tls[0].Protocols[0].Ciphers[0], read.Tls[0].Protocols[0].Ciphers[0]);
        Assert.Equal("example.com", read.Cloudflare.Zones[0].Name);
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("{}")]
    [InlineData("[1, 2, 3]")]
    [InlineData("null")]
    [InlineData("""{ "target": 5 }""")]
    public void What_is_not_a_report_is_refused_with_a_reason(string text)
    {
        var error = Assert.Throws<InvalidDataException>(() => Export.FromJson(text));
        Assert.Contains("isn't a host-dossier report", error.Message);
    }

    [Fact]
    public void A_report_saved_during_a_lookup_is_not_still_looking()
    {
        var running = Lookup.Begin(Names.ParseTarget("example.com", out _)!);
        Assert.Null(running.Finished);
        Assert.NotNull(Export.FromJson(Export.ToJson(running)).Finished);
    }

    [Fact]
    public void Addresses_stay_findable_after_reading_back()
    {
        var read = Export.FromJson(Export.ToJson(SampleData.Build()));
        Assert.Equal("AS", $"AS{read.Addresses["198.51.100.7"].Asn}"[..2]);
        Assert.Contains(read.Blocklists.Results["203.0.113.25"], r => r.Status == BlocklistStatus.Listed);
    }

    // ---- The cache ---------------------------------------------------------------------------------------------------------

    private static string TempDirectory() => Path.Combine(Path.GetTempPath(), $"host-dossier-test-{Guid.NewGuid():N}");

    [Fact]
    public void Reports_are_kept_and_found()
    {
        var directory = TempDirectory();
        try
        {
            var cache = new ReportCache(directory);
            Assert.Empty(cache.List());
            Assert.Null(cache.Load("example.com"));

            cache.Save(SampleData.Build());
            var kept = Assert.Single(cache.List());
            Assert.Equal("example.com", kept.Target);
            Assert.NotNull(cache.Find("example.com"));
            Assert.Equal("example.com", cache.Load("example.com")?.Target.Name);

            cache.Remove("example.com");
            Assert.Empty(cache.List());
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void An_old_report_is_not_fresh_and_its_time_is_the_lookups()
    {
        var directory = TempDirectory();
        try
        {
            var cache = new ReportCache(directory);
            var old = SampleData.Build();
            old.Finished = DateTimeOffset.UtcNow.AddHours(-30);
            cache.Save(old);
            Assert.Null(cache.Find("example.com", TimeSpan.FromHours(24)));
            Assert.NotNull(cache.Find("example.com", TimeSpan.FromHours(48)));
            Assert.InRange(cache.List()[0].LookedUp, old.Finished.Value.AddSeconds(-2), old.Finished.Value.AddSeconds(2));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void An_ipv6_address_makes_a_good_file_name()
    {
        var directory = TempDirectory();
        try
        {
            var cache = new ReportCache(directory);
            cache.Save(Lookup.Begin(Names.ParseTarget("2001:db8::1", out _)!));
            Assert.Equal("2001:db8::1", cache.List()[0].Target);
            Assert.Equal("2001:db8::1", cache.Load("2001:db8::1")?.Target.Name);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Only_so_many_reports_are_kept_the_oldest_going_first()
    {
        var directory = TempDirectory();
        try
        {
            var cache = new ReportCache(directory, keep: 2);
            foreach (var (name, hours) in new[] { ("a.example.com", -3), ("b.example.com", -2), ("c.example.com", -1) })
            {
                var report = Lookup.Begin(Names.ParseTarget(name, out _)!);
                report.Finished = DateTimeOffset.UtcNow.AddHours(hours);
                cache.Save(report);
            }
            Assert.Equal(["c.example.com", "b.example.com"], cache.List().Select(r => r.Target));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void A_damaged_report_is_only_not_in_the_cache()
    {
        var directory = TempDirectory();
        try
        {
            var cache = new ReportCache(directory);
            cache.Save(SampleData.Build());
            File.WriteAllText(Directory.GetFiles(directory).Single(), "damaged");
            Assert.Null(cache.Load("example.com"));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void The_token_is_never_in_a_kept_report()
    {
        var directory = TempDirectory();
        try
        {
            var report = SampleData.Build();
            new ReportCache(directory).Save(report);
            Assert.DoesNotContain("oken", File.ReadAllText(Directory.GetFiles(directory).Single()));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    // ---- Networks ---------------------------------------------------------------------------------------------------------------

    [Fact]
    public void A_network_has_a_first_and_last_address()
    {
        Assert.True(Names.TryGetRange("192.0.2.0/30", out var first, out var last, out var family));
        Assert.Equal("192.0.2.0", Names.AddressAt(first, family));
        Assert.Equal("192.0.2.3", Names.AddressAt(last, family));
        Assert.True(Names.TryGetRange("2001:db8::/126", out first, out last, out family));
        Assert.Equal("2001:db8::3", Names.AddressAt(last, family));
        Assert.True(Names.TryGetRange("0.0.0.0/0", out first, out last, out family));
        Assert.Equal("255.255.255.255", Names.AddressAt(last, family));
    }

    private const string Asn1 = "64496 | 5.6.0.0/24 | CA | arin | 2020-01-01", Asn2 = "64497 | 5.6.1.0/24 | DE | ripencc | 2021-01-01";

    [Fact]
    public async Task Routes_of_a_big_network_are_walked_with_few_questions()
    {
        using var dns = new FakeDns()
            .Text("0.0.6.5.origin.asn.cymru.com", Asn1)
            .Text("0.1.6.5.origin.asn.cymru.com", Asn2)
            .Text("AS64496.asn.cymru.com", "64496 | CA | arin | 2000-01-01 | FIRST-NET, CA")
            .Text("AS64497.asn.cymru.com", "64497 | DE | ripencc | 2000-01-01 | SECOND-NET, DE");
        var resolver = new Resolver([dns.Address]);
        var (routes, complete) = await new AddressLookup(resolver, new Rdap(new HttpClient())).RoutesAsync("5.6.0.0/23", Cancel);

        Assert.True(complete);
        Assert.Equal(["5.6.0.0/24", "5.6.1.0/24"], routes.Select(r => r.Prefix));
        Assert.Equal([64496L, 64497L], routes.Select(r => r.Asn));
        Assert.Equal(["CA", "DE"], routes.Select(r => r.Country));
        Assert.Equal("FIRST-NET", routes[0].AsName);
    }

    [Fact]
    public async Task A_gap_in_the_routes_is_crossed_and_a_limit_is_said()
    {
        using var dns = new FakeDns().Text("0.2.6.5.origin.asn.cymru.com", "64497 | 5.6.2.0/24 | DE | ripencc | 2021-01-01");
        var lookup = new AddressLookup(new Resolver([dns.Address]), new Rdap(new HttpClient()));
        var (routes, complete) = await lookup.RoutesAsync("5.6.0.0/22", Cancel);
        Assert.Equal(["5.6.2.0/24"], routes.Select(r => r.Prefix));
        Assert.True(complete);

        var (_, stopped) = await lookup.RoutesAsync("5.7.0.0/16", Cancel, maxSteps: 3);
        Assert.False(stopped);
    }

    // ---- SPF's addresses, through the whole lookup ---------------------------------------------------------------------------------

    private static Settings MailOnly(FakeDns dns) => new()
    {
        Registration = false, Dns = false, Tls = false, Ports = false, Web = false, Mail = true, Blocklists = false, FollowRelated = false,
        Resolvers = [dns.Address],
        WholeNetworkUpTo = 256,
    };

    /// <summary>A record with an include holding one address and a small network, and another holding a big network.</summary>
    private static FakeDns SpfWorld() => new FakeDns()
        .Text("example.com", "v=spf1 ip4:5.5.5.5 include:_a.example.net include:_big.example.net -all")
        .Text("_a.example.net", "v=spf1 ip4:6.6.6.6 ip4:7.7.7.0/30 -ip4:9.9.9.9 -all")
        .Text("_big.example.net", "v=spf1 ip4:5.6.0.0/23 -all")
        // The networks. Each answers for its own addresses, every one of them as Team Cymru does: the small network's
        // addresses are looked up at the same time as its routes, so none can count on another's answer being kept.
        .Text("5.5.5.5.origin.asn.cymru.com", "64496 | 5.5.5.0/24 | CA | arin | 2020-01-01")
        .Text("6.6.6.6.origin.asn.cymru.com", "64497 | 6.6.6.0/24 | DE | ripencc | 2020-01-01")
        .Text("0.7.7.7.origin.asn.cymru.com", "64498 | 7.7.7.0/24 | FR | ripencc | 2020-01-01")
        .Text("1.7.7.7.origin.asn.cymru.com", "64498 | 7.7.7.0/24 | FR | ripencc | 2020-01-01")
        .Text("2.7.7.7.origin.asn.cymru.com", "64498 | 7.7.7.0/24 | FR | ripencc | 2020-01-01")
        .Text("3.7.7.7.origin.asn.cymru.com", "64498 | 7.7.7.0/24 | FR | ripencc | 2020-01-01")
        .Text("9.9.9.9.origin.asn.cymru.com", "64499 | 9.9.9.0/24 | US | arin | 2020-01-01")
        .Text("0.0.6.5.origin.asn.cymru.com", Asn1)
        .Text("0.1.6.5.origin.asn.cymru.com", Asn2)
        .Text("AS64496.asn.cymru.com", "64496 | CA | arin | 2000-01-01 | FIRST-NET, CA")
        .Text("AS64497.asn.cymru.com", "64497 | DE | ripencc | 2000-01-01 | SECOND-NET, DE")
        .Text("AS64498.asn.cymru.com", "64498 | FR | ripencc | 2000-01-01 | THIRD-NET, FR")
        .Text("AS64499.asn.cymru.com", "64499 | US | arin | 2000-01-01 | FOURTH-NET, US")
        // Reverse names, one that leads back and one that doesn't.
        .Pointer("5.5.5.5.in-addr.arpa", "mail.example.com").Address4("mail.example.com", "5.5.5.5")
        .Pointer("6.6.6.6.in-addr.arpa", "liar.example.net");

    [Fact]
    public async Task Every_address_inside_the_chain_gets_its_as_country_and_reverse_name()
    {
        using var dns = SpfWorld();
        var dossier = Lookup.Begin(Names.ParseTarget("example.com", out _)!);
        using (var lookup = new Lookup(MailOnly(dns), new NoNetwork()))
        {
            await lookup.RunAsync(dossier, Cancel);
        }

        // Top-level, and two levels down.
        var top = dossier.Addresses["5.5.5.5"];
        Assert.Equal(64496, top.Asn);
        Assert.Equal("FIRST-NET", top.AsName);
        Assert.Equal("CA", top.Country);
        Assert.Equal(["mail.example.com"], top.ReverseNames);
        Assert.True(top.ForwardConfirmed);

        var inner = dossier.Addresses["6.6.6.6"];
        Assert.Equal(64497, inner.Asn);
        Assert.Equal("DE", inner.Country);
        Assert.Equal(["liar.example.net"], inner.ReverseNames);
        Assert.False(inner.ForwardConfirmed);

        // A small network, every address of it.
        var small = dossier.Mail!.Spf!.Networks.Single(n => n.Network == "7.7.7.0/30");
        Assert.False(small.Sampled);
        Assert.Equal(["7.7.7.0", "7.7.7.1", "7.7.7.2", "7.7.7.3"], small.Checked);
        Assert.All(small.Checked, ip => Assert.Equal("FR", dossier.Addresses[ip].Country));

        // What's listed but not allowed is still in the chain, and still looked up.
        Assert.Equal(64499, dossier.Addresses["9.9.9.9"].Asn);

        // A big network: all of it by its routes, and a sample for reverse names.
        var big = dossier.Mail.Spf.Networks.Single(n => n.Network == "5.6.0.0/23");
        Assert.True(big.Sampled);
        Assert.Equal(8, big.Checked.Count);
        Assert.Equal([64496L, 64497L], big.Routes.Select(r => r.Asn));
        Assert.DoesNotContain(dossier.Steps, s => s.State == "failed");
    }

    [Fact]
    public async Task The_chain_on_the_page_shows_each_address_under_its_term()
    {
        using var dns = SpfWorld();
        var dossier = Lookup.Begin(Names.ParseTarget("example.com", out _)!);
        using (var lookup = new Lookup(MailOnly(dns), new NoNetwork()))
        {
            await lookup.RunAsync(dossier, Cancel);
        }

        var mail = ReportBuilder.Build(dossier).Single(p => p.Key == "mail");
        var tree = mail.Blocks.OfType<TableBlock>().Single(t => t.Columns[0] == "Term or address");
        var row = (string text) => Assert.Single(tree.Rows, r => r[0].Text == text);
        string Column(IReadOnlyList<Cell> cells, string name) => cells[tree.Columns.ToList().IndexOf(name)].Text;

        // One address in the record itself: on its term's own line.
        var first = row("ip4:5.5.5.5");
        Assert.Equal("AS64496", Column(first, "AS"));
        Assert.Equal("Canada", Column(first, "Country"));
        Assert.Equal("CA", first[tree.Columns.ToList().IndexOf("Country")].Country);
        Assert.Equal("mail.example.com", Column(first, "Reverse name"));
        Assert.Equal(0, first[0].Indent);

        // Inside an include: indented under it.
        var inner = row("ip4:6.6.6.6");
        Assert.Equal(1, inner[0].Indent);
        Assert.Equal("AS64497", Column(inner, "AS"));
        Assert.Contains("doesn't lead back", Column(inner, "Reverse name"));

        // A small network has a line for itself and one for each address under it, each with its own facts.
        Assert.Equal("4 addresses", Column(row("7.7.7.0/30"), "Comes to"));
        var address = row("7.7.7.2");
        Assert.Equal("AS64498", Column(address, "AS"));
        Assert.Equal("France", Column(address, "Country"));
        Assert.Equal("None", Column(address, "Reverse name"));
        Assert.True(address[0].Indent > row("7.7.7.0/30")[0].Indent);

        // A big network says how much was looked at, and its routed parts.
        Assert.Contains("8 looked at", Column(row("5.6.0.0/23"), "Comes to"));
        Assert.Equal("AS64496", Column(row("5.6.0.0/24"), "AS"));
        Assert.Equal("Germany", Column(row("5.6.1.0/24"), "Country"));
    }

    [Fact]
    public async Task The_limit_on_lookups_falls_on_the_biggest_networks()
    {
        using var dns = SpfWorld();
        var settings = MailOnly(dns);
        settings.MailAddressLookups = 3;
        var dossier = Lookup.Begin(Names.ParseTarget("example.com", out _)!);
        using (var lookup = new Lookup(settings, new NoNetwork()))
        {
            await lookup.RunAsync(dossier, Cancel);
        }
        var spf = dossier.Mail!.Spf!;
        Assert.Single(spf.Networks.Single(n => n.Network == "5.5.5.5").Checked);
        Assert.Single(spf.Networks.Single(n => n.Network == "6.6.6.6").Checked);
        Assert.True(spf.Networks.Single(n => n.Network == "7.7.7.0/30").Sampled);
    }

    private sealed class NoNetwork : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("There's no network in the tests.");
    }
}
