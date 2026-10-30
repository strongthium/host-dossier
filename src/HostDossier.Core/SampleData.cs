namespace Strongthium.HostDossier;

/// <summary>
/// A made-up report, for the README's pictures and for trying the window: nothing is looked up. It uses only the
/// addresses, AS numbers and names set aside for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
/// 2001:db8::/32, AS64496 to AS64511, example.com, .net and .org).
/// </summary>
public static class SampleData
{
    public static Dossier Build()
    {
        var now = DateTimeOffset.UtcNow;
        var dossier = new Dossier { Target = new Target("example.com", TargetKind.Domain, "example.com", "example.com"), Started = now.AddSeconds(-47), Finished = now, MailDomain = "example.com" };

        dossier.Registration = new Registration
        {
            Domain = "example.com",
            Source = "RDAP",
            Registrar = "Example Registrar, Inc.",
            RegistrarId = "9999",
            RegistrarUrl = "https://registrar.example.net/",
            Created = now.AddYears(-11),
            Updated = now.AddMonths(-3),
            Expires = now.AddYears(2),
            DnssecSigned = false,
            AbuseEmail = "abuse@registrar.example.net",
            AbusePhone = "+1.5555550100",
        };
        dossier.Registration.Statuses.AddRange(["client transfer prohibited", "client delete prohibited"]);
        dossier.Registration.NameServers.AddRange(["ns1.example.net", "ns2.example.net"]);
        dossier.Registration.Contacts.Add(new Contact("registrant", "REDACTED FOR PRIVACY", "Example Widgets Ltd", null, null, "Ontario, CA", "CA"));
        dossier.Registration.Whois.Add(new WhoisResponse("whois.registrar.example.net", "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\nRegistrant Organization: Example Widgets Ltd\nName Server: NS1.EXAMPLE.NET\nName Server: NS2.EXAMPLE.NET\nDNSSEC: unsigned"));

        var dns = dossier.Dns;
        dns.ResolverUsed = "this computer's resolver (192.0.2.53)";
        dns.DnsProvider = "Example DNS";
        dns.Signed = false;
        dns.Records.AddRange([
            new DnsRow("example.com", "SOA", 3600, "ns1.example.net hostmaster.example.com serial 2026103001, refresh 7200, retry 3600, expire 1209600, minimum 300"),
            new DnsRow("example.com", "NS", 86400, "ns1.example.net"),
            new DnsRow("example.com", "NS", 86400, "ns2.example.net"),
            new DnsRow("example.com", "A", 300, "203.0.113.10"),
            new DnsRow("example.com", "AAAA", 300, "2001:db8:10::10"),
            new DnsRow("example.com", "MX", 3600, "10 mail.example.com"),
            new DnsRow("example.com", "MX", 3600, "20 mx2.example.net"),
            new DnsRow("example.com", "TXT", 3600, "v=spf1 ip4:203.0.113.25 ip4:198.51.100.0/28 include:_spf.example.net -all"),
            new DnsRow("example.com", "CAA", 3600, "0 issue \"ca.example.org\""),
            new DnsRow("example.com", "HTTPS", 300, "1 . alpn=h2,h3"),
        ]);
        dns.Findings.Add(new Finding(Level.Info, "DNS", "The zone isn't signed with DNSSEC."));
        dns.Findings.Add(new Finding(Level.Good, "DNS", "CAA records limit who may issue certificates."));
        dns.Subdomains.AddRange([
            new Subdomain("www.example.com", "Common name", ["203.0.113.10"]),
            new Subdomain("mail.example.com", "Common name", ["203.0.113.25"]),
            new Subdomain("api.example.com", "Certificate log", ["203.0.113.40"]),
            new Subdomain("legacy.example.com", "Cloudflare", ["192.0.2.80"]),
        ]);

        Address(dossier, "203.0.113.10", 64496, "EXAMPLE-EDGE", "203.0.113.0/24", "CA", "Example Hosting", ServiceKind.Hosting, ["web1.example.net"], "A/AAAA of example.com");
        Address(dossier, "2001:db8:10::10", 64496, "EXAMPLE-EDGE", "2001:db8:10::/48", "CA", "Example Hosting", ServiceKind.Hosting, ["web1.example.net"], "A/AAAA of example.com");
        Address(dossier, "203.0.113.25", 64496, "EXAMPLE-EDGE", "203.0.113.0/24", "CA", "Example Hosting", ServiceKind.Hosting, ["mail.example.com"], "Mail host mail.example.com");
        Address(dossier, "198.51.100.7", 64500, "EXAMPLE-MAIL", "198.51.100.0/24", "DE", "Example Mail Relay", ServiceKind.Mail, ["relay7.example.net"], "SPF 198.51.100.0/28");
        Address(dossier, "198.51.100.8", 64500, "EXAMPLE-MAIL", "198.51.100.0/24", "DE", "Example Mail Relay", ServiceKind.Mail, ["relay8.example.net"], "SPF 198.51.100.0/28");
        Address(dossier, "192.0.2.53", 64511, "EXAMPLE-DNS", "192.0.2.0/24", "NL", "Example DNS", ServiceKind.Dns, ["ns1.example.net"], "Name server ns1.example.net");
        Address(dossier, "192.0.2.80", 64505, "EXAMPLE-ORIGIN", "192.0.2.0/24", "FR", "Example Metal", ServiceKind.Hosting, ["origin.example.org"], "Real address of example.com (behind Cloudflare)");
        Address(dossier, "203.0.113.40", 64496, "EXAMPLE-EDGE", "203.0.113.0/24", "CA", "Example Hosting", ServiceKind.Hosting, [], "A/AAAA of api.example.com");
        dossier.Addresses["203.0.113.10"].Owner = new NetworkOwner { Handle = "EXAMPLE-NET-1", Name = "EXAMPLE-NET", Range = "203.0.113.0/24", Country = "CA", Organization = "Example Hosting Corp", AbuseEmail = "abuse@hosting.example.net", Registered = now.AddYears(-9), Updated = now.AddMonths(-8) };

        var tls = new TlsReport { Host = "example.com", Ip = "203.0.113.10", Port = 443, Sni = "example.com", Thorough = true, Grade = "A+", ServerChoosesCipher = true, OcspStapled = true, SecureRenegotiation = true, ExtendedMasterSecret = true, SessionTickets = true, Compression = false, FallbackProtected = true, SniRequired = true, ChainSentComplete = true, Trusted = true, NameMatches = true, TrustDetail = "Trusted by this computer's roots; not revoked." };
        var tls13 = new ProtocolResult { Name = "TLS 1.3", Supported = true };
        tls13.Ciphers.AddRange([CipherSuites.Find(0x1302), CipherSuites.Find(0x1303), CipherSuites.Find(0x1301)]);
        var tls12 = new ProtocolResult { Name = "TLS 1.2", Supported = true };
        tls12.Ciphers.AddRange([CipherSuites.Find(0xC02C), CipherSuites.Find(0xC030), CipherSuites.Find(0xCCA9), CipherSuites.Find(0xC02B), CipherSuites.Find(0xC02F), CipherSuites.Find(0xC013)]);
        tls.Protocols.AddRange([tls13, tls12, new ProtocolResult { Name = "TLS 1.1" }, new ProtocolResult { Name = "TLS 1.0" }, new ProtocolResult { Name = "SSL 3.0" }, new ProtocolResult { Name = "SSL 2.0" }]);
        tls.Groups.AddRange(["X25519MLKEM768 (post-quantum)", "x25519", "secp256r1", "secp384r1"]);
        tls.Alpn.AddRange(["h2", "http/1.1"]);
        tls.GradeReasons.Add("A+: HSTS for at least six months");
        tls.Findings.Add(new Finding(Level.Good, "TLS", "TLS 1.3 is supported."));
        tls.Findings.Add(new Finding(Level.Good, "TLS", "A post-quantum key exchange is available."));
        tls.Findings.Add(new Finding(Level.Notice, "TLS", "Some ciphers without forward secrecy are accepted."));
        tls.Chain.Add(new CertificateInfo
        {
            Subject = "CN=example.com",
            Issuer = "CN=Example Issuing CA, O=Example Trust, C=US",
            Serial = "03A1B2C3D4",
            NotBefore = now.AddDays(-30),
            NotAfter = now.AddDays(60),
            KeyType = "ECDSA",
            KeyBits = 256,
            Curve = "nistP256",
            SignatureAlgorithm = "sha256ECDSA",
            Sha256 = "9f2c84d1e0b7a65c3f18d2946ab07c5e1d83f6a29b40c7ed15a8f3b6c2d97e04",
            SpkiSha256 = "n5NmPyb1CjqEuFUvYx2zQ0dJk8rHsLtA6WeVoTiXgM4=",
            Names = ["example.com", "*.example.com"],
            Usages = ["Server Authentication", "Client Authentication"],
            Validation = "Domain validated (DV)",
            TimestampCount = 2,
            OcspUrl = "http://ocsp.example.org",
        });
        tls.Chain.Add(new CertificateInfo { Subject = "CN=Example Issuing CA, O=Example Trust, C=US", Issuer = "CN=Example Root CA, O=Example Trust, C=US", Serial = "02", NotBefore = now.AddYears(-3), NotAfter = now.AddYears(5), KeyType = "ECDSA", KeyBits = 384, SignatureAlgorithm = "sha384ECDSA", Sha256 = "", SpkiSha256 = "" });
        dossier.Tls.Add(tls);
        var mailTls = new TlsReport { Host = "mail.example.com", Ip = "203.0.113.25", Port = 25, Sni = "mail.example.com", StartTls = "smtp", Grade = "B", Trusted = true, NameMatches = true };
        var mailProtocol = new ProtocolResult { Name = "TLS 1.2", Supported = true };
        mailProtocol.Ciphers.Add(CipherSuites.Find(0xC030));
        mailTls.Protocols.AddRange([new ProtocolResult { Name = "TLS 1.3" }, mailProtocol, new ProtocolResult { Name = "TLS 1.1", Supported = true }, new ProtocolResult { Name = "TLS 1.0", Supported = true }, new ProtocolResult { Name = "SSL 3.0" }, new ProtocolResult { Name = "SSL 2.0" }]);
        mailTls.GradeReasons.Add("B: TLS 1.0 and TLS 1.1 supported");
        mailTls.Findings.Add(new Finding(Level.Warning, "TLS", "TLS 1.0 and TLS 1.1 supported. Both were retired in 2021 (RFC 8996)."));
        dossier.Tls.Add(mailTls);

        var ports = new PortReport { Ip = "203.0.113.10", Scanned = 112, Closed = 96, Filtered = 12 };
        ports.Open.AddRange([
            new OpenPort(22, "SSH", "OpenSSH", "9.6p1", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", true, false),
            new OpenPort(80, "HTTP", "nginx", null, "HTTP/1.1 301 Moved Permanently", true, false),
            new OpenPort(443, "HTTPS", null, null, "TLS", true, true),
            new OpenPort(3306, "MySQL", "MariaDB", "10.11.6-MariaDB", "10.11.6-MariaDB", true, false),
        ]);
        ports.Findings.Add(new Finding(Level.Warning, "Ports", "203.0.113.10: The database MySQL (port 3306) is reachable from the internet."));
        dossier.Ports.Add(ports);

        var web = new WebReport { Url = "https://example.com/", FinalUrl = "https://www.example.com/", Status = 200, Title = "Example Widgets", Server = "nginx", HstsMaxAge = 31536000 };
        web.Redirects.Add("https://www.example.com/");
        web.Headers.AddRange([new HttpHeader("Server", "nginx"), new HttpHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains"), new HttpHeader("Content-Type", "text/html; charset=utf-8")]);
        web.Findings.Add(new Finding(Level.Good, "Web", "HSTS is on for 365 days."));
        web.Findings.Add(new Finding(Level.Info, "Web", "No Content-Security-Policy header."));
        dossier.Web.Add(web);

        var mail = new MailReport { Domain = "example.com", Service = "Example Mail Relay" };
        var mx = new MxHost { Host = "mail.example.com", Preference = 10 };
        mx.Addresses.Add("203.0.113.25");
        var smtp = new SmtpProbe { Ip = "203.0.113.25", Banner = "mail.example.com ESMTP Postfix", StartTls = true };
        smtp.Capabilities.AddRange(["PIPELINING", "SIZE 52428800", "STARTTLS", "8BITMIME"]);
        mx.Smtp.Add(smtp);
        mx.Tlsa.Add(new TlsaRow("_25._tcp.mail.example.com", 3, 1, 1, "9f2c84d1e0b7a65c3f18d2946ab07c5e1d83f6a29b40c7ed15a8f3b6c2d97e04", true));
        var mx2 = new MxHost { Host = "mx2.example.net", Preference = 20, Service = "Example Mail Relay" };
        mx2.Addresses.Add("198.51.100.7");
        mail.Mx.AddRange([mx, mx2]);

        var spf = new SpfReport { Domain = "example.com", Record = "v=spf1 ip4:203.0.113.25 ip4:198.51.100.0/28 include:_spf.example.net -all", DnsLookups = 2, AllTerm = "-all" };
        spf.Services.Add("Example Mail Relay");
        var root = new SpfNode { Term = "v=spf1 at example.com", Mechanism = "record", Domain = "example.com" };
        var ip = new SpfNode { Term = "ip4:203.0.113.25", Mechanism = "ip4" };
        ip.Networks.Add("203.0.113.25");
        var block = new SpfNode { Term = "ip4:198.51.100.0/28", Mechanism = "ip4" };
        block.Networks.Add("198.51.100.0/28");
        var include = new SpfNode { Term = "include:_spf.example.net", Mechanism = "include", Domain = "_spf.example.net", DnsLookups = 1, Note = "Example Mail Relay" };
        var inner = new SpfNode { Term = "ip6:2001:db8:25::/48", Mechanism = "ip6" };
        inner.Networks.Add("2001:db8:25::/48");
        include.Children.AddRange([inner, new SpfNode { Term = "~all", Mechanism = "all", Qualifier = SpfQualifier.SoftFail, Note = "Everything not matched above." }]);
        root.Children.AddRange([ip, block, include, new SpfNode { Term = "-all", Mechanism = "all", Qualifier = SpfQualifier.Fail, Note = "Everything not matched above." }]);
        spf.Root = root;
        var one = new SpfNetwork { Network = "203.0.113.25", Source = "example.com › ip4:203.0.113.25", AddressCount = 1, Allowed = true };
        one.Checked.Add("203.0.113.25");
        var many = new SpfNetwork { Network = "198.51.100.0/28", Source = "example.com › ip4:198.51.100.0/28", AddressCount = 16, Allowed = true };
        many.Checked.AddRange(["198.51.100.7", "198.51.100.8"]);
        var six = new SpfNetwork { Network = "2001:db8:25::/48", Source = "example.com › include:_spf.example.net › ip6:2001:db8:25::/48", AddressCount = Math.Pow(2, 80), Allowed = true };
        spf.Networks.AddRange([one, many, six]);
        spf.Findings.Add(new Finding(Level.Good, "SPF", "The record ends in \"-all\": mail from anywhere else fails."));
        spf.Findings.Add(new Finding(Level.Info, "SPF", "It takes 2 of the 10 DNS lookups allowed."));
        mail.Spf = spf;

        var dkim = new DkimReport { Domain = "example.com", SelectorsTried = 56, DomainKeyNode = "some" };
        dkim.Keys.Add(new DkimKey { Selector = "mail", Name = "mail._domainkey.example.com", Record = "v=DKIM1; k=rsa; p=...", KeyType = "rsa", Bits = 2048 });
        dkim.Keys.Add(new DkimKey { Selector = "s1", Name = "s1._domainkey.example.com", Record = "v=DKIM1; k=rsa; p=...", KeyType = "rsa", Bits = 1024 });
        dkim.Findings.Add(new Finding(Level.Good, "DKIM", "Selector mail has a 2048-bit RSA key."));
        dkim.Findings.Add(new Finding(Level.Notice, "DKIM", "Selector s1 has a 1024-bit RSA key; 2048 is the recommendation."));
        mail.Dkim = dkim;

        var dmarc = new DmarcReport { Domain = "example.com", RecordAt = "_dmarc.example.com", Record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com", Policy = "reject" };
        dmarc.AggregateTo.Add("dmarc@example.com");
        dmarc.Findings.Add(new Finding(Level.Good, "DMARC", "The policy is reject: forged mail is refused."));
        mail.Dmarc = dmarc;

        var bimi = new BimiReport
        {
            Domain = "example.com",
            RecordAt = "default._bimi.example.com",
            Record = "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
            LogoUrl = "https://example.com/logo.svg",
            EvidenceUrl = "https://example.com/vmc.pem",
            LogoBytes = 4210,
            LogoValid = true,
            CertificateKind = "Verified Mark Certificate (VMC)",
            MarkType = "Registered Mark",
            CertificateValid = true,
            LogoMatchesCertificate = true,
            ChainDetail = "Its chain is intact up to Example Verified Mark Root, a known issuer of mark certificates.",
        };
        bimi.Findings.Add(new Finding(Level.Good, "BIMI", "The logo fits the SVG Tiny PS profile (4,210 bytes)."));
        bimi.Findings.Add(new Finding(Level.Good, "BIMI", "The logo inside the certificate is the logo published."));
        mail.Bimi = bimi;

        var sts = new MtaStsReport { Domain = "example.com", Record = "v=STSv1; id=20260101", Mode = "enforce", MaxAge = 604800, TlsRpt = "v=TLSRPTv1; rua=mailto:tls@example.com" };
        sts.PolicyMx.AddRange(["mail.example.com", "mx2.example.net"]);
        sts.Findings.Add(new Finding(Level.Good, "MTA-STS", "MTA-STS is enforcing: senders must use TLS with a valid certificate."));
        mail.MtaSts = sts;
        dossier.Mail = mail;

        var lists = dossier.Blocklists;
        lists.Lists.AddRange([
            new BlocklistHealth("bl.example.org", "Example Blocklist", true, "Answering properly."),
            new BlocklistHealth("dnsbl.example.net", "Example DNSBL", true, "Answering properly."),
            new BlocklistHealth("old.example.org", "Old Example List", false, "It says everything is listed, even the address that must never be: it's out of service or the resolver is answering for it."),
        ]);
        lists.Results["203.0.113.25"] = [new BlocklistResult("bl.example.org", BlocklistStatus.Listed, "127.0.0.2", "Listed for sending spam"), new BlocklistResult("dnsbl.example.net", BlocklistStatus.Clean, null, null)];
        lists.Results["198.51.100.7"] = [new BlocklistResult("bl.example.org", BlocklistStatus.Clean, null, null), new BlocklistResult("dnsbl.example.net", BlocklistStatus.Clean, null, null)];
        lists.Results["198.51.100.8"] = [new BlocklistResult("bl.example.org", BlocklistStatus.Clean, null, null), new BlocklistResult("dnsbl.example.net", BlocklistStatus.Clean, null, null)];
        lists.Findings.Add(new Finding(Level.Warning, "Listing", "203.0.113.25 is on bl.example.org: Listed for sending spam."));
        lists.Findings.Add(new Finding(Level.Info, "Blocklists", "1 of 3 lists couldn't be used and are left out: Old Example List."));

        var cloudflare = dossier.Cloudflare;
        cloudflare.Configured = true;
        var zone = new CloudflareZone { Name = "example.com", Id = "0000", Status = "active", Plan = "Free Website", Account = "Example Widgets", NameServers = ["ada.ns.example.net", "bob.ns.example.net"] };
        zone.Records.AddRange([
            new CloudflareRecord("example.com", "A", "192.0.2.80", true, 1, null),
            new CloudflareRecord("www.example.com", "CNAME", "example.com", true, 1, null),
            new CloudflareRecord("mail.example.com", "A", "203.0.113.25", false, 300, null),
            new CloudflareRecord("legacy.example.com", "A", "192.0.2.80", false, 300, null),
            new CloudflareRecord("example.com", "MX", "mail.example.com", false, 300, 10),
        ]);
        cloudflare.Zones.Add(zone);
        cloudflare.Findings.Add(new Finding(Level.Warning, "Cloudflare", "legacy.example.com isn't proxied and has the same address as a proxied record: it gives away the real server, 192.0.2.80."));

        var related = new RelatedDomain { Domain = "example.net", Depth = 1, Registration = new Registration { Domain = "example.net", Registrar = "Example Registrar, Inc.", Created = now.AddYears(-20) }, DmarcPolicy = "quarantine" };
        related.Reasons.AddRange(["name server of example.com", "mail host of example.com"]);
        related.Addresses.Add("192.0.2.53");
        related.MailHosts.Add("mx.example.net");
        var other = new RelatedDomain { Domain = "example.org", Depth = 2, Registration = new Registration { Domain = "example.org", Registrar = "Another Example Registrar", Created = now.AddYears(-6) } };
        other.Reasons.Add("reverse name of 192.0.2.80");
        other.Addresses.Add("192.0.2.80");
        dossier.Related.AddRange([related, other]);

        dossier.Steps.AddRange([
            new Step("Cloudflare", "done", null), new Step("Registration (RDAP and WHOIS)", "done", null), new Step("DNS records", "done", null), new Step("Names under the domain", "done", null),
            new Step("Mail", "done", null), new Step("Web server", "done", null), new Step("TLS of example.com", "done", null), new Step("Port scan", "done", null), new Step("Following related domains", "done", null),
        ]);
        return dossier;
    }

    private static void Address(Dossier dossier, string ip, long asn, string asName, string prefix, string country, string provider, ServiceKind kind, string[] reverse, string role)
    {
        var info = new AddressInfo { Ip = ip, Asn = asn, AsName = asName, Prefix = prefix, Country = country, Provider = provider, ProviderKind = kind, ForwardConfirmed = reverse.Length > 0 ? true : null };
        info.ReverseNames.AddRange(reverse);
        info.Roles.Add(role);
        dossier.Addresses[ip] = info;
    }
}
