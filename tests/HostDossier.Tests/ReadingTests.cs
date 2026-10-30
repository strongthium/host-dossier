using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Strongthium.HostDossier.Tests;

public class ReadingTests
{
    // ---- SPF, without the DNS -------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("v=spf1 -all", true)]
    [InlineData("V=SPF1 include:example.net ~all", true)]
    [InlineData("v=spf1", true)]
    [InlineData("v=spf10 -all", false)]
    [InlineData("spf1 -all", false)]
    public void Spf_records_are_recognized(string text, bool expected) => Assert.Equal(expected, SpfCheck.IsSpf(text));

    [Theory]
    [InlineData("example.net", "mail.example.com", "example.net")]
    [InlineData("%{d}", "example.com", "example.com")]
    [InlineData("_spf.%{d}", "example.com", "_spf.example.com")]
    [InlineData("%{i}._spf.%{d}", "example.com", null)]
    [InlineData("%{ir}.%{v}._spf.example.net", "example.com", null)]
    public void Spf_macros_are_filled_in_when_they_can_be(string spec, string domain, string? expected) => Assert.Equal(expected, SpfCheck.Expand(spec, domain));

    // ---- Tag lists --------------------------------------------------------------------------------------------------------

    [Fact]
    public void Tag_lists_are_read()
    {
        var tags = TagList.Parse("v=DMARC1; p=reject ; rua=mailto:a@example.com;;  bad ; pct=50");
        Assert.Equal("reject", tags["p"]);
        Assert.Equal("mailto:a@example.com", tags["rua"]);
        Assert.Equal("50", tags["pct"]);
        Assert.False(tags.ContainsKey("bad"));
    }

    // ---- DKIM -------------------------------------------------------------------------------------------------------------

    [Fact]
    public void A_dkim_key_size_comes_from_the_key()
    {
        using var rsa = RSA.Create(2048);
        var data = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
        var key = DkimCheck.ReadKey("s1", "s1._domainkey.example.com", $"v=DKIM1; k=rsa; t=y; p={data}");
        Assert.Equal(2048, key.Bits);
        Assert.True(key.Testing);
        Assert.False(key.Revoked);
        Assert.Null(key.Problem);
    }

    [Fact]
    public void An_empty_dkim_key_is_revoked()
    {
        var key = DkimCheck.ReadKey("old", "old._domainkey.example.com", "v=DKIM1; p=");
        Assert.True(key.Revoked);
    }

    [Fact]
    public void A_broken_dkim_key_is_reported()
    {
        Assert.NotNull(DkimCheck.ReadKey("x", "x._domainkey.example.com", "v=DKIM1; p=not*base64").Problem);
        Assert.NotNull(DkimCheck.ReadKey("x", "x._domainkey.example.com", "v=DKIM1; p=AAAA").Problem);
    }

    [Fact]
    public void An_ed25519_key_is_read_without_rsa()
    {
        var key = DkimCheck.ReadKey("e", "e._domainkey.example.com", "v=DKIM1; k=ed25519; p=" + Convert.ToBase64String(new byte[32]));
        Assert.Equal("ed25519", key.KeyType);
        Assert.Equal(256, key.Bits);
        Assert.Null(key.Problem);
    }

    // ---- Team Cymru -------------------------------------------------------------------------------------------------------

    [Fact]
    public void Network_answers_are_read()
    {
        var facts = AddressLookup.ParseOrigin("64496 64497 | 203.0.113.0/24 | CA | arin | 2020-01-15");
        Assert.NotNull(facts);
        Assert.Equal(64496, facts.Asn);
        Assert.Equal("203.0.113.0/24", facts.Prefix);
        Assert.Equal("CA", facts.Country);
        Assert.Equal("arin", facts.Registry);
        Assert.Null(AddressLookup.ParseOrigin("nothing here"));
        Assert.Equal("EXAMPLE-NET", AddressLookup.ParseAsName("64496 | CA | arin | 2000-03-30 | EXAMPLE-NET, CA"));
        Assert.Equal("EXAMPLE, INC.", AddressLookup.ParseAsName("64496 | US | arin | 2000-03-30 | EXAMPLE, INC."));
    }

    // ---- WHOIS --------------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("refer:        whois.example.net\n", "whois.example.net")]
    [InlineData("Registrar WHOIS Server: whois.registrar.example\n", "whois.registrar.example")]
    [InlineData("ReferralServer:  whois://whois.ripe.net:43/\n", "whois.ripe.net")]
    [InlineData("Registrar WHOIS Server: https://whois.registrar.example/\n", "whois.registrar.example")]
    [InlineData("Domain Name: EXAMPLE.COM\n", null)]
    public void Whois_referrals_are_followed(string text, string? expected) => Assert.Equal(expected, Whois.Referral(text));

    [Fact]
    public void Whois_text_fills_in_a_registration()
    {
        var registration = new Registration { Domain = "example.com" };
        registration.Whois.Add(new WhoisResponse("whois.example.net", """
            Domain Name: EXAMPLE.COM
            Registrar: Example Registrar, Inc.
            Registrar IANA ID: 9999
            Creation Date: 1995-08-14T04:00:00Z
            Registry Expiry Date: 2030-08-13T04:00:00Z
            Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
            Name Server: NS1.EXAMPLE.NET
            Name Server: NS2.EXAMPLE.NET
            DNSSEC: signedDelegation
            Registrar Abuse Contact Email: abuse@example.net
            Registrant Organization: Example Widgets Ltd
            Registrant Country: CA
            """));
        Whois.FillIn(registration);
        Assert.Equal("Example Registrar, Inc.", registration.Registrar);
        Assert.Equal(1995, registration.Created?.Year);
        Assert.Equal(2030, registration.Expires?.Year);
        Assert.Equal(["ns1.example.net", "ns2.example.net"], registration.NameServers);
        Assert.True(registration.DnssecSigned);
        Assert.Equal("abuse@example.net", registration.AbuseEmail);
        Assert.Equal("clientTransferProhibited", registration.Statuses[0]);
        Assert.Equal("Example Widgets Ltd", registration.Contacts.Find(c => c.Role == "registrant")?.Organization);
    }

    [Theory]
    [InlineData("2030-01-02T03:04:05Z", 2030)]
    [InlineData("02-Jan-2030", 2030)]
    [InlineData("2030.01.02", 2030)]
    [InlineData("2030-01-02 03:04:05 UTC", 2030)]
    [InlineData("2030/01/02", 2030)]
    public void Whois_dates_come_in_many_forms(string text, int year) => Assert.Equal(year, Whois.ParseDate(text)?.Year);

    // ---- RDAP -------------------------------------------------------------------------------------------------------------

    [Fact]
    public void An_rdap_domain_is_read()
    {
        using var json = JsonDocument.Parse("""
            {
              "ldhName": "example.com",
              "status": ["client transfer prohibited"],
              "events": [
                { "eventAction": "registration", "eventDate": "2001-02-03T00:00:00Z" },
                { "eventAction": "expiration", "eventDate": "2031-02-03T00:00:00Z" }
              ],
              "secureDNS": { "delegationSigned": true },
              "nameservers": [ { "ldhName": "NS1.EXAMPLE.NET" } ],
              "entities": [
                {
                  "roles": ["registrar"],
                  "publicIds": [ { "type": "IANA Registrar ID", "identifier": "9999" } ],
                  "vcardArray": ["vcard", [ ["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"] ]],
                  "entities": [
                    { "roles": ["abuse"], "vcardArray": ["vcard", [ ["email", {}, "text", "abuse@example.net"], ["tel", {}, "uri", "tel:+1.5555550100"] ]] }
                  ]
                },
                {
                  "roles": ["registrant"],
                  "vcardArray": ["vcard", [ ["fn", {}, "text", "A Person"], ["org", {}, "text", "Example Widgets Ltd"], ["adr", {}, "text", ["", "", "1 Example St", "Ottawa", "ON", "K1A", "CA"]] ]]
                }
              ]
            }
            """);
        var registration = new Registration { Domain = "example.com" };
        Rdap.ReadDomain(registration, json.RootElement);
        Assert.Equal("Example Registrar", registration.Registrar);
        Assert.Equal("9999", registration.RegistrarId);
        Assert.Equal(2001, registration.Created?.Year);
        Assert.Equal(2031, registration.Expires?.Year);
        Assert.True(registration.DnssecSigned);
        Assert.Equal(["ns1.example.net"], registration.NameServers);
        Assert.Equal("abuse@example.net", registration.AbuseEmail);
        Assert.Equal("+1.5555550100", registration.AbusePhone);
        var registrant = Assert.Single(registration.Contacts);
        Assert.Equal("Example Widgets Ltd", registrant.Organization);
        Assert.Contains("Ottawa", registrant.Address);
    }

    [Fact]
    public void An_rdap_network_is_read()
    {
        using var json = JsonDocument.Parse("""
            {
              "handle": "NET-203-0-113-0-1", "name": "EXAMPLE-NET", "type": "ASSIGNMENT", "country": "ca",
              "startAddress": "203.0.113.0", "endAddress": "203.0.113.255",
              "cidr0_cidrs": [ { "v4prefix": "203.0.113.0", "length": 24 } ],
              "events": [ { "eventAction": "registration", "eventDate": "2011-01-01T00:00:00Z" } ],
              "entities": [
                { "roles": ["registrant"], "handle": "EX-1", "vcardArray": ["vcard", [ ["fn", {}, "text", "Example Hosting Corp"] ]],
                  "entities": [ { "roles": ["abuse"], "vcardArray": ["vcard", [ ["email", {}, "text", "abuse@example.net"] ]] } ] }
              ]
            }
            """);
        var owner = new NetworkOwner();
        Rdap.ReadNetwork(owner, json.RootElement);
        Assert.Equal("EXAMPLE-NET", owner.Name);
        Assert.Equal("203.0.113.0/24", owner.Range);
        Assert.Equal("CA", owner.Country);
        Assert.Equal("Example Hosting Corp", owner.Organization);
        Assert.Equal("abuse@example.net", owner.AbuseEmail);
    }

    // ---- DNS records ----------------------------------------------------------------------------------------------------------

    [Fact]
    public void An_https_record_is_spelled_out()
    {
        byte[] data =
        [
            0, 1, 0, // Priority 1, target ".".
            0, 1, 0, 6, 2, (byte)'h', (byte)'2', 2, (byte)'h', (byte)'3', // alpn=h2,h3
            0, 4, 0, 4, 192, 0, 2, 1, // ipv4hint
        ];
        Assert.Equal("1 . alpn=h2,h3 ipv4hint=192.0.2.1", DnsCollector.ServiceBinding(data));
    }

    // ---- Services ---------------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("example-com.mail.protection.outlook.com", "Microsoft 365")]
    [InlineData("aspmx.l.google.com", "Google Workspace")]
    [InlineData("alt1.aspmx.l.google.com", "Google Workspace")]
    [InlineData("mxa-00000000.gslb.pphosted.com", "Proofpoint")]
    [InlineData("mail.example.com", null)]
    public void Mail_hosts_are_named(string host, string? expected) => Assert.Equal(expected, KnownServices.ForMailHost(host));

    [Theory]
    [InlineData("ada.ns.cloudflare.com", "Cloudflare")]
    [InlineData("ns-1.awsdns-01.net", "Amazon Route 53")]
    [InlineData("ns1.example.net", null)]
    public void Name_servers_are_named(string host, string? expected) => Assert.Equal(expected, KnownServices.ForNameServer(host));

    // ---- Ports -----------------------------------------------------------------------------------------------------------------

    [Fact]
    public void Port_lists_are_read() => Assert.Equal([22, 80, 8000, 8001, 8002], PortCatalog.Parse("22, 80;8000-8002, nonsense, 70000, 9-1"));

    [Theory]
    [InlineData(22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n", "SSH", "OpenSSH", "9.6p1", false)]
    [InlineData(25, "220 mail.example.com ESMTP Postfix\r\n", "SMTP", "Postfix", null, false)]
    [InlineData(21, "220 (vsFTPd 3.0.5)\r\n", "FTP", "vsFTPd", null, false)]
    [InlineData(143, "* OK Dovecot ready.\r\n", "IMAP", "Dovecot", null, false)]
    [InlineData(110, "+OK Dovecot ready.\r\n", "POP3", "Dovecot", null, false)]
    [InlineData(8080, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n", "HTTP", "nginx/1.24.0", null, false)]
    [InlineData(5900, "RFB 003.008\n", "VNC", null, "003.008", false)]
    [InlineData(6379, "+PONG\r\n", "Redis", "Redis", null, false)]
    public void Services_are_known_by_what_they_say(int port, string banner, string service, string? product, string? version, bool tls)
    {
        var found = PortScanner.Fingerprint(port, Encoding.Latin1.GetBytes(banner));
        Assert.Equal(service, found.Service);
        Assert.Equal(product, found.Product);
        Assert.Equal(version, found.Version);
        Assert.Equal(tls, found.Tls);
        Assert.True(found.Announced);
    }

    [Fact]
    public void A_tls_reply_is_called_tls()
    {
        var found = PortScanner.Fingerprint(8443, [0x16, 0x03, 0x03, 0x00, 0x40, 2]);
        Assert.True(found.Tls);
        Assert.Equal("HTTPS", found.Service);
    }

    [Fact]
    public void A_mysql_greeting_gives_its_version()
    {
        var greeting = new List<byte> { 0x20, 0, 0, 0, 10 };
        greeting.AddRange("10.11.6-MariaDB\0"u8.ToArray());
        var found = PortScanner.Fingerprint(3306, greeting.ToArray());
        Assert.Equal("MySQL", found.Service);
        Assert.Equal("MariaDB", found.Product);
        Assert.Equal("10.11.6-MariaDB", found.Version);
    }

    [Fact]
    public async Task The_port_scanner_tells_open_from_closed()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var open = ((IPEndPoint)listener.LocalEndpoint).Port;
        // A port that was just free is, almost certainly, still free: closed.
        var other = new TcpListener(IPAddress.Loopback, 0);
        other.Start();
        var closed = ((IPEndPoint)other.LocalEndpoint).Port;
        other.Stop();
        using var stop = new CancellationTokenSource();
        var server = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync(stop.Token);
                await client.GetStream().WriteAsync("SSH-2.0-Test_1.0\r\n"u8.ToArray(), stop.Token);
                await Task.Delay(2000, stop.Token);
            }
            catch (Exception exception) when (exception is OperationCanceledException or IOException or SocketException) { }
        }, TestContext.Current.CancellationToken);

        var report = await new PortScanner().ScanAsync("127.0.0.1", [open, closed], TestContext.Current.CancellationToken);
        stop.Cancel();
        listener.Stop();
        await server;

        var found = Assert.Single(report.Open);
        Assert.Equal(open, found.Port);
        Assert.Equal("SSH", found.Service);
        Assert.Equal("Test", found.Product);
        Assert.Equal(1, report.Closed);
    }

    // ---- Grades --------------------------------------------------------------------------------------------------------------

    private static TlsReport ModernServer()
    {
        var report = new TlsReport { Host = "example.com", Ip = "192.0.2.1", Port = 443, Trusted = true, NameMatches = true, SecureRenegotiation = true, Compression = false };
        var tls13 = new ProtocolResult { Name = "TLS 1.3", Supported = true };
        tls13.Ciphers.Add(CipherSuites.Find(0x1301));
        var tls12 = new ProtocolResult { Name = "TLS 1.2", Supported = true };
        tls12.Ciphers.Add(CipherSuites.Find(0xC02F));
        report.Protocols.AddRange([tls13, tls12]);
        report.Chain.Add(new CertificateInfo { Subject = "CN=example.com", Issuer = "CN=CA", Serial = "1", NotBefore = DateTimeOffset.UtcNow.AddDays(-1), NotAfter = DateTimeOffset.UtcNow.AddDays(60), KeyType = "RSA", KeyBits = 2048, SignatureAlgorithm = "sha256RSA", Sha256 = "", SpkiSha256 = "" });
        return report;
    }

    [Fact]
    public void A_modern_server_gets_an_a_and_hsts_lifts_it()
    {
        var report = ModernServer();
        TlsGrade.Apply(report);
        Assert.Equal("A", report.Grade);
        TlsGrade.ApplyHsts(report, 31536000);
        Assert.Equal("A+", report.Grade);
    }

    [Fact]
    public void Old_protocols_hold_the_grade_down_with_the_reason()
    {
        var report = ModernServer();
        var old = new ProtocolResult { Name = "TLS 1.0", Supported = true };
        old.Ciphers.Add(CipherSuites.Find(0xC013));
        report.Protocols.Add(old);
        TlsGrade.Apply(report);
        Assert.Equal("B", report.Grade);
        Assert.Contains(report.GradeReasons, r => r.Contains("TLS 1.0"));
    }

    [Theory]
    [InlineData("SSL 3.0", 0x000A, "C")]
    [InlineData("TLS 1.2", 0x0005, "C")]
    [InlineData("TLS 1.2", 0x0003, "F")]
    [InlineData("TLS 1.2", 0x0001, "F")]
    public void Bad_ciphers_and_protocols_cost_what_they_should(string protocol, ushort cipher, string grade)
    {
        var report = ModernServer();
        var bad = report.Protocols.Find(p => p.Name == protocol);
        if (bad is null)
        {
            bad = new ProtocolResult { Name = protocol, Supported = true };
            report.Protocols.Add(bad);
        }
        bad.Ciphers.Add(CipherSuites.Find(cipher));
        TlsGrade.Apply(report);
        Assert.Equal(grade, report.Grade);
    }

    [Fact]
    public void A_wrong_certificate_is_a_t_whatever_else_is_right()
    {
        var report = ModernServer();
        report.NameMatches = false;
        TlsGrade.Apply(report);
        Assert.Equal("T", report.Grade);
        TlsGrade.ApplyHsts(report, 31536000);
        Assert.Equal("T", report.Grade);
    }

    // ---- MTA-STS, DANE, Cloudflare, BIMI ----------------------------------------------------------------------------------------

    [Theory]
    [InlineData("mail.example.com", "mail.example.com", true)]
    [InlineData("*.example.com", "mail.example.com", true)]
    [InlineData("*.example.com", "a.mail.example.com", false)]
    [InlineData("*.example.com", "example.com", false)]
    [InlineData("mail.example.com", "other.example.com", false)]
    public void Mta_sts_patterns_match_one_label(string pattern, string host, bool expected) => Assert.Equal(expected, TransportChecks.MatchesPattern(pattern, host));

    [Fact]
    public void Tlsa_records_are_compared_with_the_certificate()
    {
        var report = new TlsReport { Host = "mail.example.com", Ip = "192.0.2.1", Port = 25 };
        report.Chain.Add(new CertificateInfo { Subject = "", Issuer = "", Serial = "", KeyType = "", SignatureAlgorithm = "", Sha256 = "aabb", SpkiSha256 = Convert.ToBase64String([0xCC, 0xDD]) });
        Assert.True(TransportChecks.Compare(0, 1, "aabb", report));
        Assert.True(TransportChecks.Compare(1, 1, "ccdd", report));
        Assert.False(TransportChecks.Compare(1, 1, "0000", report));
        Assert.Null(TransportChecks.Compare(1, 2, "ccdd", report)); // SHA-512 isn't compared here.
        Assert.Null(TransportChecks.Compare(1, 1, "ccdd", null));
    }

    [Fact]
    public void Cloudflare_records_are_read()
    {
        using var json = JsonDocument.Parse("""{ "name": "WWW.example.com", "type": "A", "content": "192.0.2.80", "proxied": true, "ttl": 1 }""");
        var record = CloudflareClient.ReadRecord(json.RootElement);
        Assert.Equal("www.example.com", record.Name);
        Assert.True(record.Proxied);
        Assert.Equal("192.0.2.80", record.Content);
    }

    /// <summary>The API over a made-up HTTP handler: the token goes in the right header, every page is read, and an
    /// error from Cloudflare says what it said without saying the token.</summary>
    [Fact]
    public async Task Cloudflare_is_read_page_by_page()
    {
        var handler = new FakeHandler(request =>
        {
            Assert.Equal("Bearer secret-token", request.Headers.Authorization?.ToString());
            var path = request.RequestUri!.PathAndQuery;
            if (path.Contains("zones?name=", StringComparison.Ordinal)) return """{ "success": true, "result": [ { "id": "z1", "name": "example.com", "status": "active", "plan": { "name": "Free" }, "name_servers": ["a.ns.example.net"] } ] }""";
            if (path.Contains("page=1", StringComparison.Ordinal)) return """{ "success": true, "result": [ { "name": "example.com", "type": "A", "content": "192.0.2.80", "proxied": true, "ttl": 1 } ], "result_info": { "page": 1, "total_pages": 2 } }""";
            return """{ "success": true, "result": [ { "name": "mail.example.com", "type": "A", "content": "203.0.113.25", "proxied": false, "ttl": 300 } ], "result_info": { "page": 2, "total_pages": 2 } }""";
        });
        using var http = new HttpClient(handler);
        var client = new CloudflareClient(http, "secret-token");
        var zone = await client.FindZoneAsync("example.com", TestContext.Current.CancellationToken);
        Assert.NotNull(zone);
        await client.ReadRecordsAsync(zone, TestContext.Current.CancellationToken);
        Assert.Equal(2, zone.Records.Count);
        Assert.Equal("Free", zone.Plan);
    }

    [Fact]
    public async Task A_cloudflare_error_says_what_it_said_without_the_token()
    {
        var handler = new FakeHandler(_ => """{ "success": false, "errors": [ { "code": 9109, "message": "Invalid access token" } ] }""", HttpStatusCode.Forbidden);
        using var http = new HttpClient(handler);
        var error = await Assert.ThrowsAsync<HttpRequestException>(() => new CloudflareClient(http, "secret-token").FindZoneAsync("example.com", TestContext.Current.CancellationToken));
        Assert.Contains("Invalid access token", error.Message);
        Assert.DoesNotContain("secret-token", error.Message);
    }

    [Fact]
    public void A_good_bimi_logo_passes_and_a_bad_one_says_why()
    {
        var good = new BimiReport { Domain = "example.com" };
        BimiCheck.CheckLogo("""<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100"><title>Example</title><rect width="100" height="100"/></svg>"""u8.ToArray(), good);
        Assert.True(good.LogoValid);

        var bad = new BimiReport { Domain = "example.com" };
        BimiCheck.CheckLogo("""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 50"><script>alert(1)</script></svg>"""u8.ToArray(), bad);
        Assert.False(bad.LogoValid);
        var said = bad.Findings[0].Text;
        Assert.Contains("baseProfile", said);
        Assert.Contains("script", said);
        Assert.Contains("square", said);
        Assert.Contains("title", said);

        var notXml = new BimiReport { Domain = "example.com" };
        BimiCheck.CheckLogo("this isn't xml"u8.ToArray(), notXml);
        Assert.False(notXml.LogoValid);
    }

    [Fact]
    public void A_bimi_certificate_with_no_certificates_is_invalid()
    {
        var report = new BimiReport { Domain = "example.com" };
        BimiCheck.CheckCertificate("nothing"u8.ToArray(), null, "example.com", report);
        Assert.False(report.CertificateValid);
    }

    // ---- The report ---------------------------------------------------------------------------------------------------------------

    [Fact]
    public void The_sample_makes_every_page_and_exports()
    {
        var dossier = SampleData.Build();
        var pages = ReportBuilder.Build(dossier);
        foreach (var key in (string[])["overview", "ownership", "dns", "addresses", "tls", "ports", "web", "mail", "blocklists", "cloudflare", "related", "steps"])
        {
            Assert.Contains(pages, p => p.Key == key);
        }
        var markdown = Export.ToMarkdown(dossier);
        Assert.Contains("## Overview", markdown);
        Assert.Contains("198.51.100.6/31", markdown);
        using var json = JsonDocument.Parse(Export.ToJson(dossier));
        Assert.Equal("example.com", json.RootElement.GetProperty("target").GetProperty("name").GetString());
    }

    [Fact]
    public void The_sample_uses_only_addresses_set_aside_for_documentation()
    {
        foreach (var ip in SampleData.Build().Addresses.Keys) Assert.Contains("Documentation", Names.SpecialUse(ip) ?? "");
    }

    [Fact]
    public void Settings_survive_being_saved_without_the_token()
    {
        var file = Path.Combine(Path.GetTempPath(), $"host-dossier-test-{Guid.NewGuid():N}.json");
        try
        {
            var settings = new Settings { FollowDepth = 3 };
            settings.CloudflareAccounts.Add(new CloudflareAccount { Name = "Mine", Protected = "encrypted", Token = "secret-token" });
            settings.Save(file);
            Assert.DoesNotContain("secret-token", File.ReadAllText(file));
            var loaded = Settings.Load(file);
            Assert.Equal(3, loaded.FollowDepth);
            Assert.Equal("encrypted", loaded.CloudflareAccounts[0].Protected);
            Assert.Null(loaded.CloudflareAccounts[0].Token);
            Assert.Equal(settings.BlocklistEntries.Count, loaded.BlocklistEntries.Count);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Exports_never_hold_the_token()
    {
        var dossier = SampleData.Build();
        Assert.DoesNotContain("token", Export.ToJson(dossier), StringComparison.OrdinalIgnoreCase);
    }

    private sealed class FakeHandler(Func<HttpRequestMessage, string> answer, HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(answer(request)) });
    }
}
