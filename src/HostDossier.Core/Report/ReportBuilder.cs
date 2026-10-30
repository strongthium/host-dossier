using System.Globalization;

namespace Strongthium.HostDossier;

/// <summary>
/// Lays a dossier out as pages: who owns it, what's in the DNS, where it runs, how it's secured, how its mail works.
/// The window and the text report both draw what's made here.
/// </summary>
public static class ReportBuilder
{
    // Segoe Fluent Icons, used only by the window.
    private const string IconOverview = "", IconOwner = "", IconDns = "", IconAddresses = "", IconTls = "", IconPorts = "", IconWeb = "",
        IconMail = "", IconBlock = "", IconRelated = "", IconCloud = "", IconSteps = "";

    public static List<ReportPage> Build(Dossier dossier)
    {
        lock (dossier.Sync)
        {
            var pages = new List<ReportPage>
            {
                Overview(dossier),
                Ownership(dossier),
                Dns(dossier),
                Addresses(dossier),
                Tls(dossier),
                Ports(dossier),
                Web(dossier),
                Mail(dossier),
                Blocklists(dossier),
            };
            if (dossier.Cloudflare.Configured || dossier.Cloudflare.Zones.Count > 0) pages.Add(Cloudflare(dossier));
            pages.Add(Related(dossier));
            pages.Add(Steps(dossier));
            return pages;
        }
    }

    private static Level? Worst(IEnumerable<Finding> findings)
    {
        Level? worst = null;
        foreach (var finding in findings)
        {
            if (finding.Level >= Level.Notice && (worst is null || finding.Level > worst)) worst = finding.Level;
        }
        return worst;
    }

    private static string When(DateTimeOffset? date) => date?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "";

    /// <summary>Every finding anywhere in the dossier, worst first.</summary>
    public static List<Finding> AllFindings(Dossier dossier)
    {
        var all = new List<Finding>();
        all.AddRange(RegistrationFindings(dossier));
        all.AddRange(dossier.Dns.Findings);
        all.AddRange(dossier.Tls.SelectMany(TlsFindings));
        all.AddRange(dossier.Ports.SelectMany(p => p.Findings));
        all.AddRange(dossier.Web.SelectMany(w => w.Findings));
        all.AddRange(MailFindings(dossier));
        all.AddRange(dossier.Blocklists.Findings);
        all.AddRange(dossier.Cloudflare.Findings);
        all.AddRange(dossier.Notes);
        return all.Distinct().OrderByDescending(f => f.Level).ToList();
    }

    private static IEnumerable<Finding> TlsFindings(TlsReport report)
    {
        var label = report.StartTls.Length > 0 ? $"{report.Host}:{report.Port} ({report.StartTls})" : report.Port == 443 ? report.Host : $"{report.Host}:{report.Port}";
        return report.Findings.Select(f => f with { Text = $"{label}: {f.Text}" });
    }

    private static IEnumerable<Finding> MailFindings(Dossier dossier)
    {
        if (dossier.Mail is not { } mail) return [];
        var all = new List<Finding>(mail.Findings);
        if (mail.Spf is not null) all.AddRange(mail.Spf.Findings);
        if (mail.Dkim is not null) all.AddRange(mail.Dkim.Findings);
        if (mail.Dmarc is not null) all.AddRange(mail.Dmarc.Findings);
        if (mail.Bimi is not null) all.AddRange(mail.Bimi.Findings);
        if (mail.MtaSts is not null) all.AddRange(mail.MtaSts.Findings);
        foreach (var mx in mail.Mx)
        {
            foreach (var smtp in mx.Smtp)
            {
                if (smtp.Error is null && !smtp.StartTls) all.Add(new Finding(Level.Warning, "Mail", $"{mx.Host} doesn't offer STARTTLS: mail to it travels unencrypted."));
            }
            foreach (var row in mx.Tlsa)
            {
                if (row.Matches == false) all.Add(new Finding(Level.Bad, "Mail", $"A TLSA record of {mx.Host} doesn't match its certificate: DANE senders will refuse to deliver."));
            }
        }
        return all;
    }

    private static List<Finding> RegistrationFindings(Dossier dossier)
    {
        var list = new List<Finding>();
        if (dossier.Registration is not { } registration) return list;
        var now = DateTimeOffset.UtcNow;
        if (registration.Expires is { } expires)
        {
            var days = (expires - now).TotalDays;
            if (days < 0) list.Add(new Finding(Level.Bad, "Registration", $"{registration.Domain} expired on {When(expires)}."));
            else if (days < 30) list.Add(new Finding(Level.Warning, "Registration", $"{registration.Domain} expires in {(int)days} days."));
        }
        if (registration.Created is { } created && (now - created).TotalDays < 60)
        {
            list.Add(new Finding(Level.Notice, "Registration", $"{registration.Domain} was registered on {When(created)}, only {(int)(now - created).TotalDays} days ago."));
        }
        foreach (var status in registration.Statuses)
        {
            if (status.Contains("hold", StringComparison.OrdinalIgnoreCase)) list.Add(new Finding(Level.Bad, "Registration", $"The domain's status is \"{status}\": it's kept out of the DNS."));
            else if (status.Contains("redemption", StringComparison.OrdinalIgnoreCase) || status.Contains("pendingDelete", StringComparison.OrdinalIgnoreCase)) list.Add(new Finding(Level.Bad, "Registration", $"The domain's status is \"{status}\": it's on its way to being deleted."));
        }
        return list;
    }

    // ---- Overview -----------------------------------------------------------------------------------------------------

    private static ReportPage Overview(Dossier dossier)
    {
        var facts = new List<(string, Cell)>();
        var target = dossier.Target;
        facts.Add((target.Kind == TargetKind.Domain ? "Domain" : "Address", new Cell(target.Name) { Mono = true }));
        if (target.Kind == TargetKind.Domain && target.Registrable is { } zone && zone != target.Name) facts.Add(("Registered domain", Cell.Name(zone)));

        if (dossier.Registration is { } registration)
        {
            if (target.Kind == TargetKind.Address) facts.Add(("Domain found", Cell.Name(registration.Domain)));
            var owner = registration.Contacts.Find(c => c.Role.Contains("registrant", StringComparison.OrdinalIgnoreCase));
            if ((owner?.Organization ?? owner?.Name) is { } who) facts.Add(("Registrant", who));
            if (registration.Registrar is { } registrar) facts.Add(("Registrar", registrar));
            if (registration.Created is not null || registration.Expires is not null) facts.Add(("Registered", $"{When(registration.Created)} to {When(registration.Expires)}"));
        }
        if (dossier.Dns.DnsProvider is { } dnsProvider) facts.Add(("DNS service", dnsProvider));

        // Where it runs: the public addresses, and the real ones behind Cloudflare when a token shows them.
        var hosts = dossier.Addresses.Values.Where(a => a.Roles.Exists(r => r.StartsWith($"A/AAAA of {target.Name}", StringComparison.Ordinal) || r == "The address asked about")).ToList();
        if (hosts.Count > 0) facts.Add(("Runs on", string.Join(", ", hosts.Select(ServiceName).Distinct())));
        if (hosts.FirstOrDefault(h => h.Country is not null)?.Country is { } country) facts.Add(("Country", Cell.Place(country)));
        var origins = dossier.Addresses.Values.Where(a => a.Roles.Exists(r => r.StartsWith($"Real address of {target.Name}", StringComparison.Ordinal))).ToList();
        if (origins.Count > 0) facts.Add(("Really runs on", string.Join(", ", origins.Select(o => $"{ServiceName(o)} ({o.Ip})").Distinct())));
        if (hosts.Select(h => h.Owner).FirstOrDefault(o => o?.Organization is not null)?.Organization is { } network) facts.Add(("Network owner", network));

        if (dossier.Mail is { } mail)
        {
            if (mail.Service is { } service) facts.Add(("Receives mail with", service));
            else if (mail.Mx.Count > 0) facts.Add(("Receives mail at", string.Join(", ", mail.Mx.Take(3).Select(m => m.Host))));
            if (mail.Spf?.Services is { Count: > 0 } sends) facts.Add(("Sends mail with", string.Join(", ", sends.Take(8))));
            if (mail.Dmarc?.Policy is { } policy) facts.Add(("DMARC", policy));
        }
        var grades = dossier.Tls.Where(t => t.Grade is not null && t.Port == 443).Select(t => $"{t.Grade} ({t.Ip})").Distinct().ToList();
        if (grades.Count > 0) facts.Add(("TLS grade", string.Join(", ", grades)));
        var open = dossier.Ports.SelectMany(p => p.Open.Select(o => o.Port)).Distinct().Order().ToList();
        if (open.Count > 0) facts.Add(("Open ports", string.Join(", ", open.Take(24)) + (open.Count > 24 ? $" and {open.Count - 24} more" : "")));
        var listed = dossier.Blocklists.Results.Count(r => r.Value.Exists(v => v.Status == BlocklistStatus.Listed && !v.Policy));
        var total = dossier.Blocklists.Results.Count;
        if (total > 0) facts.Add(("On blocklists", listed == 0 ? Cell.Status(Level.Good, $"None of {total} addresses checked, for abuse") : Cell.Status(Level.Warning, $"{listed} of {total} addresses checked")));

        var all = AllFindings(dossier);
        var problems = all.Where(f => f.Level >= Level.Notice).ToList();
        var good = all.Where(f => f.Level == Level.Good).ToList();
        var blocks = new List<Block>
        {
            new FactsBlock(facts),
            new HeadingBlock("What stands out", problems.Count == 0 ? (dossier.Finished is null ? "Still looking." : "Nothing that looks wrong.") : null),
        };
        if (problems.Count > 0) blocks.Add(new FindingsBlock(problems));
        if (good.Count > 0)
        {
            blocks.Add(new HeadingBlock("What's right"));
            blocks.Add(new FindingsBlock(good));
        }
        return new ReportPage("overview", "Overview", IconOverview, Worst(all), null, blocks);
    }

    private static string ServiceName(AddressInfo info) => info.Provider ?? info.AsName ?? info.Special ?? info.Ip;

    // ---- Ownership ----------------------------------------------------------------------------------------------------

    private static ReportPage Ownership(Dossier dossier)
    {
        var blocks = new List<Block>();
        if (dossier.Registration is { } registration)
        {
            blocks.Add(new HeadingBlock(registration.Domain, registration.Source is { } source ? $"The domain's registration, from {source}" : null));
            var findings = RegistrationFindings(dossier);
            if (findings.Count > 0) blocks.Add(new FindingsBlock(findings));
            AddRegistration(blocks, registration);
        }
        else if (dossier.Target.Kind == TargetKind.Domain)
        {
            blocks.Add(new NoteBlock(dossier.Finished is null ? "Looking…" : "No registration was found."));
        }

        var owned = dossier.Addresses.Values.Where(a => a.Owner is not null && a.Owner.Error is null).GroupBy(a => a.Owner!.Handle ?? a.Owner.Range ?? a.Ip).Select(g => g.First()).ToList();
        if (owned.Count > 0)
        {
            blocks.Add(new HeadingBlock("Who holds the address blocks", "From the regional internet registries' RDAP"));
            blocks.Add(new TableBlock(["Network", "Range", "Organization", "Country", "Abuse contact", "Registered", "For"],
                owned.Select(a =>
                {
                    var owner = a.Owner!;
                    return (IReadOnlyList<Cell>)[owner.Name ?? owner.Handle, Cell.Code(owner.Range), owner.Organization, Cell.Place(owner.Country), owner.AbuseEmail, When(owner.Registered), Cell.Name(a.Ip)];
                }).ToList()));
            foreach (var address in owned)
            {
                foreach (var whois in address.Owner!.Whois) blocks.Add(new RawBlock($"WHOIS for {address.Ip}, from {whois.Server}", whois.Text));
            }
        }
        var worst = Worst(RegistrationFindings(dossier));
        return new ReportPage("ownership", "Ownership", IconOwner, worst, null, blocks);
    }

    private static void AddRegistration(List<Block> blocks, Registration registration)
    {
        if (registration.Error is { } error) blocks.Add(new NoteBlock(error));
        var facts = new List<(string, Cell)>();
        void Fact(string label, string? value)
        {
            if (!string.IsNullOrEmpty(value)) facts.Add((label, value));
        }
        Fact("Registrar", registration.Registrar);
        Fact("Registrar's IANA number", registration.RegistrarId);
        Fact("Registrar's website", registration.RegistrarUrl);
        Fact("Registered", When(registration.Created));
        Fact("Changed", When(registration.Updated));
        Fact("Expires", When(registration.Expires));
        if (registration.DnssecSigned is { } signed) Fact("DNSSEC at the registry", signed ? "Signed" : "Not signed");
        Fact("Abuse contact", string.Join(", ", new[] { registration.AbuseEmail, registration.AbusePhone }.Where(s => !string.IsNullOrEmpty(s))));
        if (registration.Statuses.Count > 0) Fact("Status", string.Join(", ", registration.Statuses));
        if (facts.Count > 0) blocks.Add(new FactsBlock(facts));
        if (registration.NameServers.Count > 0)
        {
            blocks.Add(new HeadingBlock("Name servers at the registry"));
            blocks.Add(new TableBlock(["Name server", "Service"], registration.NameServers.Select(n => (IReadOnlyList<Cell>)[Cell.Name(n), KnownServices.ForNameServer(n)]).ToList()));
        }
        if (registration.Contacts.Count > 0)
        {
            blocks.Add(new HeadingBlock("Contacts", "Most registries now hide these, and show \"redacted\""));
            blocks.Add(new TableBlock(["Role", "Name", "Organization", "Email", "Phone", "Address"],
                registration.Contacts.Select(c => (IReadOnlyList<Cell>)[c.Role, c.Name, c.Organization, c.Email, c.Phone, c.Address]).ToList()));
        }
        foreach (var whois in registration.Whois) blocks.Add(new RawBlock($"WHOIS from {whois.Server}", whois.Text));
    }

    // ---- DNS ------------------------------------------------------------------------------------------------------------

    private static ReportPage Dns(Dossier dossier)
    {
        var report = dossier.Dns;
        var blocks = new List<Block>();
        var facts = new List<(string, Cell)>();
        if (report.ResolverUsed is { } resolver) facts.Add(("Asked through", resolver));
        if (report.DnsProvider is { } provider) facts.Add(("DNS service", provider));
        if (facts.Count > 0) blocks.Add(new FactsBlock(facts));
        if (report.Findings.Count > 0) blocks.Add(new FindingsBlock(report.Findings));
        blocks.Add(new HeadingBlock("Records"));
        var order = new[] { "SOA", "NS", "A", "AAAA", "CNAME", "MX", "TXT", "CAA", "HTTPS", "SVCB", "SRV", "DS", "DNSKEY", "TLSA", "SSHFP", "NAPTR", "URI" };
        var rows = report.Records.OrderBy(r => r.Name, StringComparer.Ordinal).ThenBy(r => Array.IndexOf(order, r.Type) is var i and >= 0 ? i : 99).ThenBy(r => r.Value, StringComparer.Ordinal)
            .Select(r => (IReadOnlyList<Cell>)[Cell.Code(r.Name), r.Type, r.Ttl.ToString(CultureInfo.InvariantCulture), r.Type is "NS" or "A" or "AAAA" or "CNAME" ? Cell.Name(r.Value) : Cell.Code(r.Value)])
            .ToList();
        blocks.Add(new TableBlock(["Name", "Type", "TTL", "Value"], rows, dossier.Finished is null ? "Looking…" : "No records."));
        if (report.Problems.Count > 0) blocks.Add(new NoteBlock("Queries that failed: " + string.Join("; ", report.Problems)));

        blocks.Add(new HeadingBlock("Names under the domain", "Common names that answered, names in the public certificate logs that still resolve, and a Cloudflare zone's names"));
        blocks.Add(new TableBlock(["Name", "Found by", "Addresses", "Service"],
            report.Subdomains.OrderBy(s => s.Name, StringComparer.Ordinal).Select(s => (IReadOnlyList<Cell>)[
                Cell.Name(s.Name), s.Source, Cell.Code(string.Join(", ", s.Addresses.Take(4))),
                string.Join(", ", s.Addresses.Select(a => dossier.Addresses.GetValueOrDefault(a)).OfType<AddressInfo>().Select(ServiceName).Distinct().Take(3))]).ToList(),
            dossier.Finished is null ? "Looking…" : "None found."));
        if (report.SubdomainsNote is { } note) blocks.Add(new NoteBlock(note));
        return new ReportPage("dns", "DNS", IconDns, Worst(report.Findings), report.Records.Count > 0 ? report.Records.Count.ToString(CultureInfo.InvariantCulture) : null, blocks);
    }

    // ---- Addresses --------------------------------------------------------------------------------------------------------

    private static ReportPage Addresses(Dossier dossier)
    {
        var blocks = new List<Block>();
        var all = dossier.Addresses.Values.ToList();
        var groups = new[]
        {
            ("Where it runs", (Func<AddressInfo, bool>)(a => a.Roles.Exists(r => r.StartsWith("A/AAAA of " + dossier.Target.Name, StringComparison.Ordinal) || r == "The address asked about" || r.StartsWith("Real address of", StringComparison.Ordinal)))),
            ("Name servers", a => a.Roles.Exists(r => r.StartsWith("Name server", StringComparison.Ordinal))),
            ("Mail hosts", a => a.Roles.Exists(r => r.StartsWith("Mail host", StringComparison.Ordinal))),
            ("Other names under the domain", a => a.Roles.Exists(r => r.StartsWith("A/AAAA of ", StringComparison.Ordinal) && r.EndsWith("." + (dossier.Target.Registrable ?? dossier.Target.Name), StringComparison.Ordinal))),
            ("Related domains", a => true),
        };
        var used = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (title, test) in groups)
        {
            var members = all.Where(a => !a.Roles.TrueForAll(r => r.StartsWith("SPF ", StringComparison.Ordinal)) && test(a) && used.Add(a.Ip)).OrderBy(a => a.Ip, StringComparer.Ordinal).ToList();
            if (members.Count == 0) continue;
            blocks.Add(new HeadingBlock(title));
            blocks.Add(AddressTable(members));
        }
        var spfOnly = all.Count(a => a.Roles.TrueForAll(r => r.StartsWith("SPF ", StringComparison.Ordinal)));
        if (spfOnly > 0) blocks.Add(new NoteBlock($"The {spfOnly} addresses that only come from SPF are on the Mail page, in the SPF record."));
        if (blocks.Count == 0) blocks.Add(new NoteBlock(dossier.Finished is null ? "Looking…" : "No addresses were found."));
        return new ReportPage("addresses", "Addresses", IconAddresses, null, all.Count > 0 ? all.Count.ToString(CultureInfo.InvariantCulture) : null, blocks);
    }

    internal static TableBlock AddressTable(IEnumerable<AddressInfo> addresses) =>
        new(["Address", "Service", "AS", "Network name", "Prefix", "Country", "Reverse name", "Why it's here"],
            addresses.Select(a => (IReadOnlyList<Cell>)[
                Cell.Name(a.Ip),
                a.Special ?? a.Provider ?? "",
                a.Asn is { } asn ? $"AS{asn}" : "",
                a.AsName,
                Cell.Code(a.Prefix),
                Cell.Place(a.Country),
                a.ReverseNames.Count == 0 ? "" : new Cell(string.Join(", ", a.ReverseNames.Take(2)) + (a.ForwardConfirmed == false ? " (doesn't lead back)" : "")) { Lookup = a.ReverseNames[0], Mono = true },
                string.Join("; ", a.Roles.Take(3)) + (a.Roles.Count > 3 ? $"; and {a.Roles.Count - 3} more" : ""),
            ]).ToList());

    // ---- TLS --------------------------------------------------------------------------------------------------------------

    private static ReportPage Tls(Dossier dossier)
    {
        var blocks = new List<Block>();
        var reports = dossier.Tls.OrderBy(t => t.Port == 443 ? 0 : 1).ThenBy(t => t.Host, StringComparer.Ordinal).ThenBy(t => t.Port).ToList();
        if (reports.Count == 0) blocks.Add(new NoteBlock(dossier.Finished is null ? "Testing…" : "Nothing answered with TLS, or the test is turned off."));
        if (reports.Count > 1)
        {
            blocks.Add(new TableBlock(["Host", "Address", "Port", "Grade", "Protocols", "Certificate"],
                reports.Select(t => (IReadOnlyList<Cell>)[Cell.Name(t.Host), Cell.Name(t.Ip), t.Port.ToString(CultureInfo.InvariantCulture) + (t.StartTls.Length > 0 ? $" ({t.StartTls})" : ""),
                    t.Error is not null ? Cell.Status(Level.Notice, "No TLS") : GradeCell(t.Grade), string.Join(", ", t.Protocols.Where(p => p.Supported).Select(p => p.Name)),
                    t.Chain.Count > 0 ? ShortName(t.Chain[0].Subject) : ""]).ToList()));
        }
        foreach (var report in reports) AddTlsReport(blocks, report);
        var worst = Worst(reports.SelectMany(r => r.Findings));
        var best = reports.Select(r => r.Grade).FirstOrDefault(g => g is not null);
        return new ReportPage("tls", "TLS", IconTls, worst, best, blocks);
    }

    private static Cell GradeCell(string? grade) => grade switch
    {
        null => "",
        "A+" or "A" or "A-" => Cell.Status(Level.Good, grade),
        "B" => Cell.Status(Level.Notice, grade),
        "C" or "D" or "E" => Cell.Status(Level.Warning, grade),
        _ => Cell.Status(Level.Bad, grade),
    };

    private static string ShortName(string subject)
    {
        foreach (var part in subject.Split(','))
        {
            var text = part.Trim();
            if (text.StartsWith("CN=", StringComparison.Ordinal)) return text[3..];
        }
        return subject;
    }

    private static void AddTlsReport(List<Block> blocks, TlsReport report)
    {
        var title = report.StartTls.Length > 0 ? $"{report.Host}, port {report.Port} with STARTTLS ({report.StartTls})" : $"{report.Host}, port {report.Port}";
        blocks.Add(new HeadingBlock(title, $"At {report.Ip}. " + (report.Thorough ? "Every protocol and cipher tested." : "A quick test: each protocol, its choice of cipher, and whether a bad one is accepted.")));
        if (report.Error is { } error)
        {
            blocks.Add(new NoteBlock(error));
            return;
        }
        var facts = new List<(string, Cell)> { ("Grade", GradeCell(report.Grade)) };
        if (report.GradeReasons.Count > 0) facts.Add(("Why", string.Join("; ", report.GradeReasons)));
        void Yes(string label, bool? value, bool wanted = true)
        {
            if (value is { } answer) facts.Add((label, Cell.Status(answer == wanted ? Level.Good : Level.Notice, answer ? "Yes" : "No")));
        }
        if (report.ServerChoosesCipher is { } chooses) facts.Add(("Cipher order", chooses ? "The server's" : "The client's"));
        if (report.Groups.Count > 0) facts.Add(("Key exchange groups", string.Join(", ", report.Groups)));
        if (report.DhBits is { } dh) facts.Add(("Diffie-Hellman", $"{dh} bits"));
        if (report.Alpn.Count > 0) facts.Add(("ALPN", string.Join(", ", report.Alpn)));
        Yes("OCSP stapled", report.OcspStapled);
        Yes("Secure renegotiation", report.SecureRenegotiation);
        Yes("Extended master secret", report.ExtendedMasterSecret);
        if (report.SessionTickets is { } tickets) facts.Add(("Session tickets", tickets ? "Yes" : "No"));
        Yes("TLS compression", report.Compression, wanted: false);
        Yes("Refuses a downgrade", report.FallbackProtected);
        if (report.SniRequired is { } sni) facts.Add(("Certificate depends on the name", sni ? "Yes" : "No"));
        blocks.Add(new FactsBlock(facts));
        if (report.Findings.Count > 0) blocks.Add(new FindingsBlock(report.Findings));

        var protocols = report.Protocols.Select(p => (IReadOnlyList<Cell>)[p.Name, p.Supported
            ? Cell.Status(p.Name is "SSL 2.0" or "SSL 3.0" ? Level.Bad : p.Name is "TLS 1.0" or "TLS 1.1" ? Level.Warning : Level.Good, "Yes")
            : "No"]).ToList();
        blocks.Add(new TableBlock(["Protocol", "Supported"], protocols));
        var rows = new List<IReadOnlyList<Cell>>();
        foreach (var protocol in report.Protocols.Where(p => p.Supported))
        {
            foreach (var cipher in protocol.Ciphers)
            {
                rows.Add([protocol.Name, Cell.Code(cipher.Name), cipher.KeyExchange, cipher.Encryption, cipher.Bits.ToString(CultureInfo.InvariantCulture), cipher.ForwardSecret ? "Yes" : "No", StrengthCell(cipher.Strength)]);
            }
        }
        if (rows.Count > 0) blocks.Add(new TableBlock(["Protocol", "Cipher", "Key exchange", "Encryption", "Bits", "Forward secrecy", "Strength"], rows));

        if (report.Chain.Count > 0)
        {
            blocks.Add(new HeadingBlock("Certificate", report.TrustDetail));
            var leaf = report.Chain[0];
            var certificate = new List<(string, Cell)>
            {
                ("Subject", leaf.Subject),
                ("Names", new Cell(string.Join(", ", leaf.Names.Take(40)) + (leaf.Names.Count > 40 ? $" and {leaf.Names.Count - 40} more" : "")) { Mono = true }),
                ("Issuer", leaf.Issuer),
                ("Valid", $"{When(leaf.NotBefore)} to {When(leaf.NotAfter)}"),
                ("Key", $"{leaf.KeyType}{(leaf.KeyBits > 0 ? $" {leaf.KeyBits} bits" : "")}{(leaf.Curve is { } curve ? $" ({curve})" : "")}"),
                ("Signature", leaf.SignatureAlgorithm),
                ("Kind", leaf.Validation ?? "Unknown"),
                ("Public logs", leaf.TimestampCount > 0 ? $"{leaf.TimestampCount} timestamps" : "None embedded"),
                ("SHA-256", Cell.Code(leaf.Sha256)),
                ("Key pin (SHA-256)", Cell.Code(leaf.SpkiSha256)),
            };
            if (report.NameMatches is { } matches) certificate.Insert(2, ("Matches the name", Cell.Status(matches ? Level.Good : Level.Bad, matches ? "Yes" : "No")));
            if (report.ChainSentComplete is { } complete) certificate.Add(("Server sends the whole chain", Cell.Status(complete ? Level.Good : Level.Warning, complete ? "Yes" : "No")));
            if (leaf.OcspUrl is { } ocsp) certificate.Add(("OCSP", ocsp));
            if (leaf.CrlUrl is { } crl) certificate.Add(("CRL", crl));
            if (leaf.MustStaple) certificate.Add(("Must be stapled", "Yes"));
            blocks.Add(new FactsBlock(certificate));
            if (report.Chain.Count > 1)
            {
                blocks.Add(new TableBlock(["Chain", "Issued by", "Until", "Key", "Signature"],
                    report.Chain.Select(c => (IReadOnlyList<Cell>)[ShortName(c.Subject), ShortName(c.Issuer), When(c.NotAfter), $"{c.KeyType} {c.KeyBits}", c.SignatureAlgorithm]).ToList()));
            }
        }
    }

    private static Cell StrengthCell(string strength) => strength switch
    {
        CipherSuites.Strong => Cell.Status(Level.Good, strength),
        CipherSuites.Acceptable => Cell.Status(Level.Info, strength),
        CipherSuites.Weak => Cell.Status(Level.Warning, strength),
        _ => Cell.Status(Level.Bad, strength),
    };

    // ---- Ports ------------------------------------------------------------------------------------------------------------

    private static ReportPage Ports(Dossier dossier)
    {
        var blocks = new List<Block>();
        if (dossier.Ports.Count == 0) blocks.Add(new NoteBlock(dossier.Finished is null ? "Scanning…" : "No ports were scanned."));
        foreach (var report in dossier.Ports.OrderBy(p => p.Ip, StringComparer.Ordinal))
        {
            var info = dossier.Addresses.GetValueOrDefault(report.Ip);
            blocks.Add(new HeadingBlock(report.Ip, report.Skipped ?? $"{(info is null ? "" : ServiceName(info) + ". ")}{report.Scanned} ports tried: {report.Open.Count} open, {report.Closed} closed, {report.Filtered} filtered (no answer)"));
            if (report.Skipped is not null) continue;
            if (report.Findings.Count > 0) blocks.Add(new FindingsBlock(report.Findings));
            blocks.Add(new TableBlock(["Port", "Service", "Product", "Version", "TLS", "Says", "Known by"],
                report.Open.Select(p => (IReadOnlyList<Cell>)[p.Port.ToString(CultureInfo.InvariantCulture), p.Service, p.Product, p.Version, p.Tls ? "Yes" : "", Cell.Code(p.Banner), p.Announced ? "What it said" : "The port number only"]).ToList(),
                "No open ports."));
        }
        var open = dossier.Ports.Sum(p => p.Open.Count);
        return new ReportPage("ports", "Ports", IconPorts, Worst(dossier.Ports.SelectMany(p => p.Findings)), open > 0 ? open.ToString(CultureInfo.InvariantCulture) : null, blocks);
    }

    // ---- Web --------------------------------------------------------------------------------------------------------------

    private static ReportPage Web(Dossier dossier)
    {
        var blocks = new List<Block>();
        if (dossier.Web.Count == 0) blocks.Add(new NoteBlock(dossier.Finished is null ? "Asking…" : "The web server wasn't asked."));
        foreach (var report in dossier.Web)
        {
            blocks.Add(new HeadingBlock(report.Url));
            if (report.Error is { } error)
            {
                blocks.Add(new NoteBlock(error));
                continue;
            }
            var facts = new List<(string, Cell)>();
            if (report.Status is { } status) facts.Add(("Status", status.ToString(CultureInfo.InvariantCulture)));
            if (report.Redirects.Count > 0) facts.Add(("Redirects to", string.Join(" → ", report.Redirects)));
            if (report.Title is { } title) facts.Add(("Title", title));
            if (report.Server is { } server) facts.Add(("Server", server));
            blocks.Add(new FactsBlock(facts));
            if (report.Findings.Count > 0) blocks.Add(new FindingsBlock(report.Findings));
            if (report.Headers.Count > 0) blocks.Add(new RawBlock("Response headers", string.Join("\n", report.Headers.Select(h => $"{h.Name}: {h.Value}"))));
        }
        return new ReportPage("web", "Web", IconWeb, Worst(dossier.Web.SelectMany(w => w.Findings)), null, blocks);
    }

    // ---- Mail -------------------------------------------------------------------------------------------------------------

    private static ReportPage Mail(Dossier dossier)
    {
        var blocks = new List<Block>();
        if (dossier.Mail is not { } mail)
        {
            blocks.Add(new NoteBlock(dossier.Finished is null ? "Looking…" : "There's no domain to look at the mail of."));
            return new ReportPage("mail", "Mail", IconMail, null, null, blocks);
        }
        if (mail.Domain != dossier.Target.Name) blocks.Add(new NoteBlock($"These are the settings of {mail.Domain}."));

        // Receiving
        blocks.Add(new HeadingBlock("Where mail is received", mail.Service is { } service ? service : null));
        if (mail.Findings.Count > 0) blocks.Add(new FindingsBlock(mail.Findings));
        blocks.Add(new TableBlock(["Pref.", "Mail host", "Service", "Addresses", "Says", "STARTTLS", "TLS grade"],
            mail.Mx.OrderBy(m => m.Preference).Select(mx =>
            {
                var probe = mx.Smtp.FirstOrDefault();
                var tls = dossier.Tls.Find(t => t.Host == mx.Host && t.Port == 25);
                return (IReadOnlyList<Cell>)[mx.Preference.ToString(CultureInfo.InvariantCulture), Cell.Name(mx.Host), mx.Service, Cell.Code(string.Join(", ", mx.Addresses.Take(3))),
                    probe?.Error is { } failed ? Cell.Status(Level.Info, failed) : Cell.Code(probe?.Banner), probe is null || probe.Error is not null ? "" : Cell.Status(probe.StartTls ? Level.Good : Level.Warning, probe.StartTls ? "Yes" : "No"), GradeCell(tls?.Grade)];
            }).ToList(), "No MX records."));
        if (mail.Mx.Exists(m => m.Smtp.Exists(s => s.Error is not null)))
        {
            blocks.Add(new NoteBlock("A mail host that didn't answer may only be out of reach from here: many internet providers block outgoing connections to port 25."));
        }
        var tlsa = mail.Mx.SelectMany(m => m.Tlsa).ToList();
        if (tlsa.Count > 0)
        {
            blocks.Add(new HeadingBlock("DANE (TLSA records)"));
            blocks.Add(new TableBlock(["Name", "Usage", "Selector", "Matching", "Data", "Matches the certificate"],
                tlsa.Select(row => (IReadOnlyList<Cell>)[Cell.Code(row.Name), row.Usage.ToString(CultureInfo.InvariantCulture), row.Selector.ToString(CultureInfo.InvariantCulture), row.Matching.ToString(CultureInfo.InvariantCulture), Cell.Code(row.Data),
                    row.Matches is { } matches ? Cell.Status(matches ? Level.Good : Level.Bad, matches ? "Yes" : "No") : "Not compared"]).ToList()));
        }

        AddSpf(blocks, dossier, mail);
        AddDkim(blocks, mail);
        AddDmarc(blocks, mail);
        AddBimi(blocks, mail);
        AddMtaSts(blocks, mail);
        return new ReportPage("mail", "Mail", IconMail, Worst(MailFindings(dossier)), null, blocks);
    }

    private static void AddSpf(List<Block> blocks, Dossier dossier, MailReport mail)
    {
        blocks.Add(new HeadingBlock("SPF: who may send", mail.Spf is null ? "Looking…" : null));
        if (mail.Spf is not { } spf) return;
        if (spf.Findings.Count > 0) blocks.Add(new FindingsBlock(spf.Findings));
        if (spf.Record is null) return;
        var facts = new List<(string, Cell)> { ("Record", Cell.Code(spf.Record)) };
        if (spf.Services.Count > 0) facts.Add(("Comes to", string.Join(", ", spf.Services)));
        blocks.Add(new FactsBlock(facts));

        // The record as a tree: each term, what it comes to, and down to every address with who it is.
        var tree = new List<IReadOnlyList<Cell>>();
        var shown = new HashSet<string>(StringComparer.Ordinal);
        void AddNetwork(string text, int depth)
        {
            var network = spf.Networks.Find(n => n.Network == text);
            if (network is null) return;
            var label = new Cell(text) { Indent = depth, Mono = true };
            if (!shown.Add(text))
            {
                tree.Add([label, "", "Listed above", "", "", "", "", ""]);
                return;
            }
            if (network.AddressCount == 1)
            {
                tree.Add([label with { Lookup = text }, "", "", .. AddressCells(dossier, text)]);
                return;
            }
            var count = network.AddressCount.ToString(network.AddressCount < 1e9 ? "N0" : "0.##e+0", CultureInfo.InvariantCulture);
            var size = network.Sampled ? $"{count} addresses, {network.Checked.Count} looked at" : $"{count} addresses";
            var whole = network.Routes.Count == 1 ? network.Routes[0] : null;
            tree.Add([label, "", size, whole?.Provider ?? whole?.AsName, whole is null ? "" : $"AS{whole.Asn}", Cell.Place(whole?.Country), "", ""]);
            if (network.Routes.Count > 1)
            {
                foreach (var route in network.Routes)
                {
                    tree.Add([new Cell(route.Prefix) { Indent = depth + 1, Mono = true }, "", "Routed part", route.Provider ?? route.AsName, $"AS{route.Asn}", Cell.Place(route.Country), "", ""]);
                }
            }
            if (!network.RoutesComplete) tree.Add([new Cell("…") { Indent = depth + 1 }, "", "More routed parts than were followed", "", "", "", "", ""]);
            foreach (var ip in network.Checked)
            {
                tree.Add([new Cell(ip) { Indent = depth + 1, Mono = true, Lookup = ip }, "", "", .. AddressCells(dossier, ip)]);
            }
        }
        void Walk(SpfNode node, int depth)
        {
            foreach (var child in node.Children)
            {
                var term = new Cell(child.Term) { Indent = depth, Mono = true, Lookup = child.Mechanism is "include" or "redirect" or "a" or "mx" ? child.Domain : null };
                // An ip4: of one address is that address: a line for each would only say it twice.
                if (child.Mechanism is "ip4" or "ip6" && child.Error is null && child.Networks.Count == 1 && !child.Networks[0].Contains('/') && shown.Add(child.Networks[0]))
                {
                    tree.Add([term with { Lookup = child.Networks[0] }, QualifierText(child), "", .. AddressCells(dossier, child.Networks[0])]);
                }
                else
                {
                    Cell result = child.Error is { } error ? Cell.Status(Level.Bad, error) : child.Networks.Count > 0 ? "" : child.Note;
                    tree.Add([term, QualifierText(child), result, "", "", "", "", ""]);
                    foreach (var network in child.Networks) AddNetwork(network, depth + 1);
                }
                Walk(child, depth + 1);
            }
        }
        if (spf.Root is not null) Walk(spf.Root, 0);
        blocks.Add(new HeadingBlock("The record, resolved", $"{spf.DnsLookups} DNS lookups. Term by term, down to each address and who it is. Small networks are listed whole; for a big one, each routed part, and a sample of addresses spread across it"));
        blocks.Add(new TableBlock(["Term or address", "If it matches", "Comes to", "Service", "AS", "Country", "Reverse name", "Blocklists"], tree));

        // Every network, with who it is.
        blocks.Add(new HeadingBlock("Networks allowed to send", "Every network the record comes to, each once, with who holds it"));
        var rows = new List<IReadOnlyList<Cell>>();
        foreach (var network in spf.Networks.OrderBy(n => n.Allowed ? 0 : 1).ThenBy(n => n.Network.Contains(':') ? 1 : 0))
        {
            var infos = network.Checked.Select(ip => dossier.Addresses.GetValueOrDefault(ip)).OfType<AddressInfo>().ToList();
            var first = infos.FirstOrDefault(i => i.Asn is not null) ?? infos.FirstOrDefault();
            var ases = network.Routes.Select(r => $"AS{r.Asn}").Concat(infos.Where(i => i.Asn is not null).Select(i => $"AS{i.Asn}")).Distinct().ToList();
            var countries = network.Routes.Select(r => r.Country).Concat(infos.Select(i => i.Country)).OfType<string>().Distinct().ToList();
            var reverse = infos.SelectMany(i => i.ReverseNames).Distinct().ToList();
            var hits = network.Checked.Count(ip => dossier.Blocklists.Results.GetValueOrDefault(ip)?.Exists(r => r.Status == BlocklistStatus.Listed) == true);
            var checkedCount = network.Checked.Count(ip => dossier.Blocklists.Results.ContainsKey(ip));
            rows.Add([
                Cell.Name(network.Network.Contains('/') ? network.Network[..network.Network.IndexOf('/')] : network.Network) with { Text = network.Network },
                network.Allowed ? network.AddressCount.ToString("N0", CultureInfo.InvariantCulture) : Cell.Status(Level.Info, "Not allowed"),
                first is null ? "" : first.Provider ?? first.AsName,
                string.Join(", ", ases.Take(3)),
                countries.Count == 0 ? "" : Cell.Place(countries[0]) with { Text = Countries.Name(countries[0]) + (countries.Count > 1 ? $" and {countries.Count - 1} more" : "") },
                new Cell(string.Join(", ", reverse.Take(2)) + (reverse.Count > 2 ? $" and {reverse.Count - 2} more" : "")) { Mono = true },
                checkedCount == 0 ? "" : hits > 0 ? Cell.Status(Level.Warning, $"{hits} of {checkedCount} listed") : Cell.Status(Level.Good, $"{checkedCount} clean"),
                network.Sampled ? $"{network.Checked.Count} of {network.AddressCount:N0}" : "All",
                new Cell(network.Source),
            ]);
        }
        blocks.Add(new TableBlock(["Network", "Addresses", "Service", "AS", "Country", "Reverse names", "Blocklists", "Looked at", "From"], rows, "The record allows no networks."));
    }

    /// <summary>Who an address is: its service, AS, country, reverse name and whether it's on a blocklist.</summary>
    private static Cell[] AddressCells(Dossier dossier, string ip)
    {
        if (dossier.Addresses.GetValueOrDefault(ip) is not { } info) return ["", "", "", dossier.Finished is null ? "Looking…" : "", ""];
        Cell reverse = info.ReverseNames.Count > 0
            ? new Cell(string.Join(", ", info.ReverseNames.Take(2)) + (info.ForwardConfirmed == false ? " (doesn't lead back)" : "")) { Lookup = info.ReverseNames[0], Mono = true }
            : info.ReverseNote ?? (info.Special is null ? "None" : "");
        // Blank would look like nothing to report: only some addresses fit the limit on blocklist checks.
        Cell lists = dossier.Finished is not null && dossier.Blocklists.Lists.Count > 0 ? "Not checked" : "";
        if (dossier.Blocklists.Results.GetValueOrDefault(ip) is { } results)
        {
            var hits = results.Where(r => r.Status == BlocklistStatus.Listed).ToList();
            lists = hits.Count > 0
                ? Cell.Status(hits.TrueForAll(h => h.Policy) ? Level.Info : Level.Warning, string.Join(", ", hits.Select(h => h.Zone)))
                : Cell.Status(Level.Good, "Clean");
        }
        return [info.Special ?? info.Provider ?? info.AsName, info.Asn is { } asn ? $"AS{asn}" : "", Cell.Place(info.Country), reverse, lists];
    }

    private static string QualifierText(SpfNode node) =>node.Mechanism is "exp" or "redirect" or "include" && node.Mechanism != "include" ? "" : node.Qualifier switch
    {
        SpfQualifier.Pass => "Pass",
        SpfQualifier.Fail => "Fail",
        SpfQualifier.SoftFail => "Soft fail",
        _ => "Neutral",
    };

    private static void AddDkim(List<Block> blocks, MailReport mail)
    {
        blocks.Add(new HeadingBlock("DKIM", mail.Dkim is { } tried ? $"{tried.SelectorsTried} common selectors tried. The DNS can't list them, and Settings can add more" : "Looking…"));
        if (mail.Dkim is not { } dkim) return;
        if (dkim.Findings.Count > 0) blocks.Add(new FindingsBlock(dkim.Findings));
        if (dkim.Keys.Count > 0)
        {
            blocks.Add(new TableBlock(["Selector", "Service", "Key", "Bits", "Testing", "Name"],
                dkim.Keys.Select(k => (IReadOnlyList<Cell>)[Cell.Code(k.Selector), k.Service, k.Revoked ? "Revoked" : k.KeyType, k.Bits > 0 ? k.Bits.ToString(CultureInfo.InvariantCulture) : "", k.Testing ? "Yes" : "", Cell.Code(k.Name)]).ToList()));
        }
    }

    private static void AddDmarc(List<Block> blocks, MailReport mail)
    {
        blocks.Add(new HeadingBlock("DMARC", mail.Dmarc is null ? "Looking…" : null));
        if (mail.Dmarc is not { } dmarc) return;
        if (dmarc.Findings.Count > 0) blocks.Add(new FindingsBlock(dmarc.Findings));
        if (dmarc.Record is null) return;
        var facts = new List<(string, Cell)>
        {
            ("Record at", Cell.Code(dmarc.RecordAt)),
            ("Record", Cell.Code(dmarc.Record)),
            ("Policy", dmarc.Policy),
            ("For subdomains", dmarc.SubdomainPolicy ?? $"The same ({dmarc.Policy})"),
            ("Applies to", $"{dmarc.Percent}% of mail"),
            ("Alignment", $"DKIM {(dmarc.AlignDkim == "s" ? "strict" : "relaxed")}, SPF {(dmarc.AlignSpf == "s" ? "strict" : "relaxed")}"),
        };
        if (dmarc.AggregateTo.Count > 0) facts.Add(("Aggregate reports to", string.Join(", ", dmarc.AggregateTo)));
        if (dmarc.FailureTo.Count > 0) facts.Add(("Failure reports to", string.Join(", ", dmarc.FailureTo)));
        blocks.Add(new FactsBlock(facts));
    }

    private static void AddBimi(List<Block> blocks, MailReport mail)
    {
        blocks.Add(new HeadingBlock("BIMI", mail.Bimi is null ? "Looking…" : null));
        if (mail.Bimi is not { } bimi) return;
        if (bimi.Record is null)
        {
            blocks.Add(new NoteBlock("No BIMI record."));
            return;
        }
        if (bimi.Findings.Count > 0) blocks.Add(new FindingsBlock(bimi.Findings));
        var facts = new List<(string, Cell)> { ("Record at", Cell.Code(bimi.RecordAt)), ("Record", Cell.Code(bimi.Record)) };
        if (bimi.LogoUrl is { } logo) facts.Add(("Logo", Cell.Link(logo)));
        if (bimi.LogoValid is { } valid) facts.Add(("Fits SVG Tiny PS", Cell.Status(valid ? Level.Good : Level.Warning, valid ? "Yes" : "No")));
        if (bimi.EvidenceUrl is { } evidence) facts.Add(("Certificate", Cell.Link(evidence)));
        if (bimi.CertificateKind is { } kind) facts.Add(("Kind", kind));
        if (bimi.MarkType is { } mark) facts.Add(("Mark", mark));
        if (bimi.CertificateValid is { } certificate) facts.Add(("Certificate valid", Cell.Status(certificate ? Level.Good : Level.Bad, certificate ? "Yes" : "No")));
        if (bimi.ChainDetail is { } chain) facts.Add(("Chain", chain));
        if (bimi.LogoMatchesCertificate is { } same) facts.Add(("Same logo in the certificate", Cell.Status(same ? Level.Good : Level.Bad, same ? "Yes" : "No")));
        blocks.Add(new FactsBlock(facts));
        if (bimi.Chain.Count > 0)
        {
            blocks.Add(new TableBlock(["Certificate", "Issued by", "Until", "Names"],
                bimi.Chain.Select(c => (IReadOnlyList<Cell>)[ShortName(c.Subject), ShortName(c.Issuer), When(c.NotAfter), Cell.Code(string.Join(", ", c.Names.Take(4)))]).ToList()));
        }
    }

    private static void AddMtaSts(List<Block> blocks, MailReport mail)
    {
        blocks.Add(new HeadingBlock("MTA-STS and TLS reporting", mail.MtaSts is null ? "Looking…" : null));
        if (mail.MtaSts is not { } sts) return;
        if (sts.Findings.Count > 0) blocks.Add(new FindingsBlock(sts.Findings));
        var facts = new List<(string, Cell)>();
        if (sts.Record is { } record) facts.Add(("Record", Cell.Code(record)));
        if (sts.Mode is { } mode) facts.Add(("Mode", mode));
        if (sts.PolicyMx.Count > 0) facts.Add(("Mail hosts in the policy", Cell.Code(string.Join(", ", sts.PolicyMx))));
        if (sts.MaxAge is { } age) facts.Add(("Kept by senders for", $"{age / 86400} days"));
        if (sts.TlsRpt is { } rpt) facts.Add(("TLS-RPT", Cell.Code(rpt)));
        if (facts.Count > 0) blocks.Add(new FactsBlock(facts));
    }

    // ---- Blocklists ---------------------------------------------------------------------------------------------------------

    private static ReportPage Blocklists(Dossier dossier)
    {
        var report = dossier.Blocklists;
        var blocks = new List<Block>();
        if (report.Findings.Count > 0) blocks.Add(new FindingsBlock(report.Findings));
        if (report.Results.Count > 0)
        {
            var listed = report.Results.Where(r => r.Value.Exists(v => v.Status == BlocklistStatus.Listed)).ToList();
            blocks.Add(new HeadingBlock("Addresses checked", $"{report.Results.Count} addresses: {listed.Count} on at least one list"));
            blocks.Add(new TableBlock(["Address", "Service", "Country", "Why it's here", "Listed on", "Clean on", "Failed"],
                report.Results.OrderByDescending(r => r.Value.Count(v => v.Status == BlocklistStatus.Listed)).ThenBy(r => r.Key, StringComparer.Ordinal).Select(r =>
                {
                    var info = dossier.Addresses.GetValueOrDefault(r.Key);
                    var hits = r.Value.Where(v => v.Status == BlocklistStatus.Listed).ToList();
                    return (IReadOnlyList<Cell>)[Cell.Name(r.Key), info is null ? "" : ServiceName(info), Cell.Place(info?.Country), info is null ? "" : string.Join("; ", info.Roles.Take(2)),
                        hits.Count > 0 ? Cell.Status(hits.TrueForAll(h => h.Policy) ? Level.Info : Level.Warning, string.Join(", ", hits.Select(h => h.Zone))) : Cell.Status(Level.Good, "None"),
                        r.Value.Count(v => v.Status == BlocklistStatus.Clean).ToString(CultureInfo.InvariantCulture),
                        r.Value.Count(v => v.Status is BlocklistStatus.Failed or BlocklistStatus.Refused).ToString(CultureInfo.InvariantCulture)];
                }).ToList()));
        }
        if (report.Lists.Count > 0)
        {
            blocks.Add(new HeadingBlock("The lists", "Each is tried on its test addresses first. Which lists are asked is in Settings"));
            blocks.Add(new TableBlock(["List", "Zone", "Usable", "How it answered"],
                report.Lists.Select(l => (IReadOnlyList<Cell>)[l.Name, Cell.Code(l.Zone), Cell.Status(l.Usable ? Level.Good : Level.Notice, l.Usable ? "Yes" : "No"), l.Detail]).ToList()));
        }
        if (blocks.Count == 0) blocks.Add(new NoteBlock(dossier.Finished is null ? "Checking…" : "No addresses were checked."));
        var hitCount = report.Results.Count(r => r.Value.Exists(v => v.Status == BlocklistStatus.Listed && !v.Policy));
        return new ReportPage("blocklists", "Blocklists", IconBlock, Worst(report.Findings), hitCount > 0 ? hitCount.ToString(CultureInfo.InvariantCulture) : null, blocks);
    }

    // ---- Cloudflare -----------------------------------------------------------------------------------------------------------

    private static ReportPage Cloudflare(Dossier dossier)
    {
        var report = dossier.Cloudflare;
        var blocks = new List<Block>();
        if (report.Findings.Count > 0) blocks.Add(new FindingsBlock(report.Findings));
        foreach (var error in report.Errors) blocks.Add(new NoteBlock(error));
        foreach (var zone in report.Zones)
        {
            blocks.Add(new HeadingBlock(zone.Name, $"{zone.Records.Count} records from Cloudflare's API, as stored: not what the public DNS shows"));
            var facts = new List<(string, Cell)>();
            if (zone.Account is { } account) facts.Add(("Account", account));
            if (zone.Plan is { } plan) facts.Add(("Plan", plan));
            if (zone.Status is { } status) facts.Add(("Status", status));
            if (zone.NameServers.Count > 0) facts.Add(("Name servers", Cell.Code(string.Join(", ", zone.NameServers))));
            if (facts.Count > 0) blocks.Add(new FactsBlock(facts));
            blocks.Add(new TableBlock(["Name", "Type", "Content", "Proxied", "Really on", "AS", "Country", "Reverse name"],
                zone.Records.OrderBy(r => r.Name, StringComparer.Ordinal).ThenBy(r => r.Type, StringComparer.Ordinal).Select(r =>
                {
                    var info = dossier.Addresses.GetValueOrDefault(r.Content);
                    return (IReadOnlyList<Cell>)[Cell.Name(r.Name), r.Type, r.Type is "A" or "AAAA" or "CNAME" ? Cell.Name(r.Content) : Cell.Code(r.Content), r.Proxied ? "Yes" : "",
                        info is null ? "" : ServiceName(info), info?.Asn is { } asn ? $"AS{asn}" : "", Cell.Place(info?.Country), Cell.Code(info?.ReverseNames.FirstOrDefault())];
                }).ToList()));
        }
        if (blocks.Count == 0) blocks.Add(new NoteBlock(dossier.Finished is null ? "Asking…" : "No zone found."));
        return new ReportPage("cloudflare", "Cloudflare", IconCloud, Worst(report.Findings), null, blocks);
    }

    // ---- Related ----------------------------------------------------------------------------------------------------------------

    private static ReportPage Related(Dossier dossier)
    {
        var blocks = new List<Block>();
        if (dossier.Related.Count == 0)
        {
            blocks.Add(new NoteBlock(dossier.Finished is null ? "Following…" : "No other domains came up."));
        }
        else
        {
            blocks.Add(new HeadingBlock("Other domains that came up", "Each got a short look: who registered it and where it runs. Click one to look it up fully"));
            blocks.Add(new TableBlock(["Domain", "How it's related", "Steps away", "Registrar", "Registered", "Runs on", "Mail hosts", "DMARC"],
                dossier.Related.OrderBy(r => r.Depth).ThenBy(r => r.Domain, StringComparer.Ordinal).Select(r =>
                {
                    var service = r.Addresses.Select(a => dossier.Addresses.GetValueOrDefault(a)).OfType<AddressInfo>().Select(ServiceName).Distinct().Take(3);
                    return (IReadOnlyList<Cell>)[Cell.Name(r.Domain), string.Join("; ", r.Reasons.Take(3)), r.Depth.ToString(CultureInfo.InvariantCulture), r.Registration?.Registrar, When(r.Registration?.Created), string.Join(", ", service), Cell.Code(string.Join(", ", r.MailHosts.Take(2))), r.DmarcPolicy];
                }).ToList()));
        }
        foreach (var note in dossier.Notes) blocks.Add(new NoteBlock(note.Text));
        return new ReportPage("related", "Related", IconRelated, null, dossier.Related.Count > 0 ? dossier.Related.Count.ToString(CultureInfo.InvariantCulture) : null, blocks);
    }

    private static ReportPage Steps(Dossier dossier)
    {
        var blocks = new List<Block>
        {
            new TableBlock(["Step", "State", "Detail"], dossier.Steps.Select(s => (IReadOnlyList<Cell>)[s.Name,
                s.State switch { "failed" => Cell.Status(Level.Warning, "Failed"), "running" => Cell.Status(Level.Info, "Running"), "stopped" => Cell.Status(Level.Notice, "Stopped"), _ => Cell.Status(Level.Good, "Done") }, s.Detail]).ToList()),
        };
        var failed = dossier.Steps.Exists(s => s.State == "failed");
        return new ReportPage("steps", "Steps", IconSteps, failed ? Level.Warning : null, null, blocks);
    }
}
