using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using DnsClient;
using DnsClient.Protocol;

namespace Strongthium.HostDossier;

/// <summary>
/// The lookup: takes a domain or an address and finds out as much as it can, following what it finds. Names lead to
/// addresses, addresses to networks and reverse names, certificates, mail records and name servers to other domains,
/// and each of those gets a shorter look of its own, as far as the settings allow. Whatever can't be found is
/// reported in the dossier's steps; one failing part doesn't stop the others.
/// </summary>
public sealed class Lookup : IDisposable
{
    private readonly Settings settings;
    private readonly HttpClient http;
    private readonly HttpClient probeHttp;
    private readonly Resolver resolver;
    private readonly Rdap rdap;
    private readonly AddressLookup addressLookup;
    private readonly DnsCollector collector;
    private readonly BlocklistCheck blocklists;
    private readonly TlsScanner tlsScanner = new();
    private readonly ConcurrentDictionary<string, Lazy<Task<AddressInfo>>> addresses = new();
    private readonly SemaphoreSlim addressGate = new(24);

    private Dossier dossier = null!;
    private CancellationToken cancel;
    private List<BlocklistEntry> usableLists = [];
    private Task? blocklistHealth;
    private readonly HashSet<string> blocklistChecked = [];
    private int mailBudget;
    private readonly System.Diagnostics.Stopwatch blocklistClock = new();
    /// <summary>Domains to take a short look at, with the reason and how far from the target.</summary>
    private readonly ConcurrentDictionary<string, RelatedDomain> related = new();

    private const string UserAgent = "host-dossier (+https://github.com/strongthium/host-dossier)";

    public Lookup(Settings settings, HttpMessageHandler? handler = null)
    {
        this.settings = settings;
        http = new HttpClient(handler ?? new SocketsHttpHandler { AutomaticDecompression = DecompressionMethods.All }, disposeHandler: handler is null) { Timeout = Timeout.InfiniteTimeSpan };
        http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        // The web probe has to read sites with bad certificates too, which the TLS test reports. It sends nothing secret.
        probeHttp = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All,
            SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true },
        }) { Timeout = Timeout.InfiniteTimeSpan };
        probeHttp.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        resolver = new Resolver(settings.Resolvers);
        rdap = new Rdap(http);
        addressLookup = new AddressLookup(resolver, rdap);
        collector = new DnsCollector(resolver, http);
        blocklists = new BlocklistCheck(settings.Resolvers.Count > 0 ? [resolver, new Resolver([])] : [resolver]);
        mailBudget = settings.MailAddressBudget;
    }

    public void Dispose()
    {
        http.Dispose();
        probeHttp.Dispose();
        addressGate.Dispose();
    }

    public static Dossier Begin(Target target) => new() { Target = target };

    public async Task RunAsync(Dossier target, CancellationToken cancellation)
    {
        dossier = target;
        cancel = cancellation;
        dossier.Change(() =>
        {
            dossier.Dns.ResolverUsed = resolver.Description;
            dossier.Blocklists.Budget = settings.MailAddressBudget;
            dossier.Cloudflare.Configured = settings.CloudflareAccounts.Exists(a => !string.IsNullOrEmpty(a.Token));
        });
        try
        {
            if (dossier.Target.Kind == TargetKind.Domain) await DomainAsync().ConfigureAwait(false);
            else await AddressTargetAsync().ConfigureAwait(false);
            if (settings.FollowRelated) await Step("Following related domains", FollowRelatedAsync).ConfigureAwait(false);
            CrossCheckCloudflare();
        }
        finally
        {
            dossier.Change(() => dossier.Finished = DateTimeOffset.UtcNow);
        }
    }

    // ---- Steps -----------------------------------------------------------------------------------------------------

    private async Task Step(string name, Func<Task> work)
    {
        dossier.Change(() => dossier.Steps.Add(new Step(name, "running", null)));
        string state = "done";
        string? detail = null;
        try
        {
            await work().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested)
        {
            state = "stopped";
        }
        catch (Exception exception)
        {
            // Whatever went wrong here is this step's: it's shown, and the rest carries on.
            state = "failed";
            detail = exception.GetBaseException().Message;
        }
        dossier.Change(() =>
        {
            var index = dossier.Steps.FindIndex(s => s.Name == name && s.State == "running");
            if (index >= 0) dossier.Steps[index] = new Step(name, state, detail);
        });
    }

    // ---- A domain ----------------------------------------------------------------------------------------------------

    private async Task DomainAsync()
    {
        var name = dossier.Target.Name;
        var zone = dossier.Target.Registrable ?? name;
        var cloudflare = settings.CloudflareAccounts.Exists(a => !string.IsNullOrEmpty(a.Token)) ? Step("Cloudflare", () => CloudflareAsync(zone)) : Task.CompletedTask;
        var registration = settings.Registration
            ? Step("Registration (RDAP and WHOIS)", async () =>
            {
                var found = await RegistrationAsync(zone, full: true).ConfigureAwait(false);
                dossier.Change(() => dossier.Registration = found);
            })
            : Task.CompletedTask;

        var hostAddresses = new List<string>();
        await Step("DNS records", async () =>
        {
            foreach (var query in new[] { name, zone }.Distinct())
            {
                var rows = await collector.RecordsAsync(query, text => dossier.Change(() => dossier.Dns.Problems.Add(text)), cancel).ConfigureAwait(false);
                dossier.Change(() =>
                {
                    foreach (var row in rows)
                    {
                        if (!dossier.Dns.Records.Contains(row)) dossier.Dns.Records.Add(row);
                    }
                });
            }
            await collector.DnssecAsync(zone, dossier.Dns, cancel).ConfigureAwait(false);
            var servers = await resolver.NameServersAsync(zone, cancel).ConfigureAwait(false);
            dossier.Change(() => dossier.Dns.DnsProvider = servers.Select(KnownServices.ForNameServer).FirstOrDefault(s => s is not null));
            foreach (var server in servers) Relate(server, $"name server of {zone}", 1);
            JudgeDns(zone, servers);
            hostAddresses.AddRange(await resolver.AddressesAsync(name, cancel).ConfigureAwait(false));
            foreach (var row in dossier.Read(() => dossier.Dns.Records.Where(r => r.Type == "CNAME").ToList())) Relate(row.Value, $"{row.Name} points to it", 1);
            await Task.WhenAll(servers.Select(async server =>
            {
                foreach (var ip in await resolver.AddressesAsync(server, cancel).ConfigureAwait(false))
                {
                    await AddressAsync(ip, $"Name server {server}", withOwner: false).ConfigureAwait(false);
                }
            })).ConfigureAwait(false);
        }).ConfigureAwait(false);
        await Task.WhenAll(hostAddresses.Select(ip => AddressAsync(ip, $"A/AAAA of {name}", withOwner: true))).ConfigureAwait(false);

        var subdomains = settings.Dns ? Step("Names under the domain", () => SubdomainsAsync(zone)) : Task.CompletedTask;
        var mail = settings.Mail ? Step("Mail", () => MailAsync(name, zone)) : Task.CompletedTask;
        var web = settings.Web ? Step("Web server", () => WebAsync($"https://{name}/", $"http://{name}/")) : Task.CompletedTask;
        await cloudflare.ConfigureAwait(false);

        var scanTargets = hostAddresses.Concat(dossier.Read(() => OriginAddressesOf(name))).Distinct().ToList();
        var tls = settings.Tls ? Step($"TLS of {name}", () => TlsForNameAsync(name, hostAddresses)) : Task.CompletedTask;
        await Task.WhenAll(registration, subdomains, mail, web, tls).ConfigureAwait(false);
        if (settings.Tls && dossier.Read(() => OriginAddressesOf(name)).Count > 0) await Step("TLS of the real server behind Cloudflare", () => OriginTlsAsync(name)).ConfigureAwait(false);
        ApplyHsts();

        if (settings.Ports) await Step("Port scan", () => PortsAsync(scanTargets, name)).ConfigureAwait(false);
    }

    private void JudgeDns(string zone, IReadOnlyList<string> servers)
    {
        var report = dossier.Dns;
        dossier.Change(() =>
        {
            if (servers.Count == 1) report.Findings.Add(new Finding(Level.Warning, "DNS", $"{zone} has only one name server: if it fails, the domain disappears."));
            if (report.Signed == true) report.Findings.Add(new Finding(Level.Good, "DNS", report.ValidatedByResolver == true ? "The zone is signed with DNSSEC, and the resolver checked it." : "The zone is signed with DNSSEC (the resolver in use doesn't check signatures)."));
            else if (report.Signed == false) report.Findings.Add(new Finding(Level.Info, "DNS", "The zone isn't signed with DNSSEC."));
            var caa = report.Records.Exists(r => r.Type == "CAA");
            report.Findings.Add(caa ? new Finding(Level.Good, "DNS", "CAA records limit who may issue certificates.") : new Finding(Level.Info, "DNS", "No CAA records: any certificate authority may issue for the domain."));
        });
    }

    private async Task SubdomainsAsync(string zone)
    {
        var wildcard = await collector.WildcardAsync(zone, cancel).ConfigureAwait(false);
        dossier.Change(() => dossier.Dns.WildcardAddresses = wildcard);
        if (wildcard.Count > 0)
        {
            dossier.Change(() => dossier.Dns.Findings.Add(new Finding(Level.Info, "DNS", $"The zone has a wildcard: every name under it answers ({string.Join(", ", wildcard)}).")));
        }

        var common = collector.CommonNamesAsync(zone, wildcard, cancel);
        var logs = settings.CertificateLogs ? collector.CertificateLogsAsync(zone, wildcard, cancel) : Task.FromResult<(List<Subdomain>, string?)>(([], null));
        await Task.WhenAll(common, logs).ConfigureAwait(false);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var all = common.Result.Concat(logs.Result.Item1).Where(s => seen.Add(s.Name)).OrderBy(s => s.Name, StringComparer.Ordinal).ToList();
        dossier.Change(() =>
        {
            dossier.Dns.Subdomains.AddRange(all);
            dossier.Dns.SubdomainsNote = logs.Result.Item2;
        });
        // Their addresses are worth knowing; the ownership of each block is asked for only with a named service in the way.
        var unique = all.SelectMany(s => s.Addresses.Select(a => (Address: a, s.Name))).DistinctBy(p => p.Address).Take(120);
        await Task.WhenAll(unique.Select(p => AddressAsync(p.Address, $"A/AAAA of {p.Name}", withOwner: false))).ConfigureAwait(false);
    }

    // ---- An address ----------------------------------------------------------------------------------------------------

    private async Task AddressTargetAsync()
    {
        var ip = dossier.Target.Name;
        AddressInfo info = null!;
        await Step("Address", async () =>
        {
            info = await AddressAsync(ip, "The address asked about", withOwner: true).ConfigureAwait(false);
            if (settings.Registration && info.Special is null)
            {
                var whois = await Whois.LookUpAsync(ip, cancel).ConfigureAwait(false);
                dossier.Change(() => info.Owner?.Whois.AddRange(whois));
            }
        }).ConfigureAwait(false);
        if (info is null || info.Special is not null) return;

        var tls = settings.Tls ? Step($"TLS of {ip}", () => TlsForNameAsync(ip, [ip])) : Task.CompletedTask;
        var web = settings.Web ? Step("Web server", () => WebAsync($"https://{FormatHost(ip)}/", $"http://{FormatHost(ip)}/")) : Task.CompletedTask;
        var ports = settings.Ports ? Step("Port scan", () => PortsAsync([ip], null)) : Task.CompletedTask;
        var blocklist = settings.Blocklists ? Step("Blocklists", () => CheckBlocklistsAsync([ip])) : Task.CompletedTask;
        await Task.WhenAll(tls, web, ports, blocklist).ConfigureAwait(false);

        // The domain behind the address: its reverse name, unless that's only the network's own naming, else its certificate.
        var cloudOrCdn = info.ProviderKind is ServiceKind.Cloud or ServiceKind.Cdn or ServiceKind.Isp;
        var fromName = cloudOrCdn ? null : info.ReverseNames.Select(Names.RegistrableDomain).FirstOrDefault(n => n is not null);
        var fromCertificate = dossier.Read(() => dossier.Tls.SelectMany(t => t.CertificateNames).ToList())
            .Pipe(Certificates.FollowableNames).Select(Names.RegistrableDomain).FirstOrDefault(n => n is not null);
        var domain = fromName ?? fromCertificate;
        foreach (var name in info.ReverseNames) Relate(name, $"reverse name of {ip}", 1);
        if (domain is not null)
        {
            if (settings.Registration)
            {
                await Step($"Registration of {domain}", async () =>
                {
                    var found = await RegistrationAsync(domain, full: true).ConfigureAwait(false);
                    dossier.Change(() => dossier.Registration = found);
                }).ConfigureAwait(false);
            }
            if (settings.Mail) await Step($"Mail of {domain}", () => MailAsync(domain, domain)).ConfigureAwait(false);
        }
    }

    private static string FormatHost(string ip) => ip.Contains(':') ? $"[{ip}]" : ip;

    // ---- Addresses -----------------------------------------------------------------------------------------------------

    /// <summary>An address's facts, looked up once however many things lead to it; each adds the role it found it in.</summary>
    private async Task<AddressInfo> AddressAsync(string ip, string role, bool withOwner)
    {
        var info = await addresses.GetOrAdd(ip, key => new Lazy<Task<AddressInfo>>(async () =>
        {
            var created = new AddressInfo { Ip = key };
            await addressGate.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                await addressLookup.FillAsync(created, withOwner: false, cancel).ConfigureAwait(false);
            }
            finally
            {
                addressGate.Release();
            }
            dossier.Change(() => dossier.Addresses[key] = created);
            return created;
        })).Value.ConfigureAwait(false);
        dossier.Change(() =>
        {
            if (!info.Roles.Contains(role)) info.Roles.Add(role);
        });
        if (withOwner && info.Owner is null)
        {
            await addressGate.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                var holder = new AddressInfo { Ip = info.Ip, Prefix = info.Prefix, Special = info.Special };
                await addressLookup.FillOwnerAsync(holder, cancel).ConfigureAwait(false);
                dossier.Change(() => info.Owner ??= holder.Owner);
            }
            finally
            {
                addressGate.Release();
            }
        }
        return info;
    }

    // ---- Ownership -----------------------------------------------------------------------------------------------------

    private async Task<Registration> RegistrationAsync(string domain, bool full)
    {
        var registration = new Registration { Domain = domain };
        var rdapFound = await rdap.DomainAsync(registration, cancel).ConfigureAwait(false);
        if (full || !rdapFound)
        {
            registration.Whois.AddRange(await Whois.LookUpAsync(domain, cancel).ConfigureAwait(false));
            Whois.FillIn(registration);
        }
        if (!rdapFound && registration.Registrar is null && registration.Created is null) registration.Error = "Neither RDAP nor WHOIS had anything for this domain.";
        return registration;
    }

    // ---- TLS and the web -------------------------------------------------------------------------------------------------

    private async Task TlsForNameAsync(string name, IReadOnlyList<string> ips)
    {
        var isAddress = Names.IsAddress(name);
        var sni = isAddress ? null : name;
        var chosen = ips.Where(ip => Names.SpecialUse(ip) is null && Names.CanReach(ip)).Take(settings.TlsAddresses).ToList();
        if (ips.Count > 0 && chosen.Count == 0 && ips.All(ip => !Names.CanReach(ip)))
        {
            dossier.Change(() => dossier.Notes.Add(new Finding(Level.Info, "TLS", $"{name} only has IPv6 addresses, and this computer has no IPv6 connection: its TLS couldn't be tested.")));
        }
        await Task.WhenAll(chosen.Select(async ip =>
        {
            var report = await tlsScanner.ScanAsync(name, ip, 443, sni, "", thorough: true, cancel).ConfigureAwait(false);
            AddTls(report);
        })).ConfigureAwait(false);

        // The common sibling name, if it's somewhere else.
        if (!isAddress && !name.StartsWith("www.", StringComparison.Ordinal) && name == dossier.Target.Registrable)
        {
            var www = $"www.{name}";
            var wwwIps = await resolver.AddressesAsync(www, cancel).ConfigureAwait(false);
            if (wwwIps.Count > 0 && !wwwIps.Exists(chosen.Contains))
            {
                var report = await tlsScanner.ScanAsync(www, wwwIps[0], 443, www, "", thorough: false, cancel).ConfigureAwait(false);
                AddTls(report);
            }
        }
    }

    private void AddTls(TlsReport report)
    {
        dossier.Change(() => dossier.Tls.Add(report));
        if (report.Chain.Count == 0) return;
        foreach (var name in Certificates.FollowableNames(report.Chain[0].Names).Take(25))
        {
            Relate(name, $"on the certificate of {report.Host}", 1);
        }
    }

    private void ApplyHsts()
    {
        dossier.Change(() =>
        {
            var age = dossier.Web.Select(w => w.HstsMaxAge).FirstOrDefault(a => a is not null);
            foreach (var report in dossier.Tls.Where(t => t.Port == 443 && t.Thorough)) TlsGrade.ApplyHsts(report, age);
        });
    }

    private async Task WebAsync(string secure, string plain)
    {
        var probe = new WebProbe(probeHttp);
        var https = probe.FetchAsync(secure, cancel);
        var http = probe.FetchAsync(plain, cancel);
        await Task.WhenAll(https, http).ConfigureAwait(false);
        var fromPlain = http.Result;
        if (fromPlain.Error is null && fromPlain.FinalUrl?.StartsWith("http:", StringComparison.OrdinalIgnoreCase) == true && https.Result.Error is null)
        {
            fromPlain.Findings.Add(new Finding(Level.Notice, "Web", $"{plain} stays on plain HTTP rather than redirecting to HTTPS."));
        }
        else if (fromPlain.Error is null && fromPlain.FinalUrl?.StartsWith("https:", StringComparison.OrdinalIgnoreCase) == true)
        {
            fromPlain.Findings.Add(new Finding(Level.Good, "Web", "Plain HTTP redirects to HTTPS."));
        }
        dossier.Change(() =>
        {
            dossier.Web.Add(https.Result);
            dossier.Web.Add(fromPlain);
        });
        foreach (var redirect in https.Result.Redirects.Concat(fromPlain.Redirects))
        {
            if (Uri.TryCreate(redirect, UriKind.Absolute, out var uri)) Relate(uri.Host, "the website redirects to it", 1);
        }
    }

    // ---- Ports ------------------------------------------------------------------------------------------------------------

    private async Task PortsAsync(IReadOnlyList<string> ips, string? name)
    {
        var ports = PortCatalog.Parse(settings.PortList);
        var scanner = new PortScanner(settings.PortConcurrency, settings.PortTimeoutMs);
        var targetIsAddress = dossier.Target.Kind == TargetKind.Address;
        var mxAddresses = dossier.Read(() => dossier.Mail?.Mx.Where(m => m.Service is null).SelectMany(m => m.Addresses).ToList() ?? []);
        var chosen = ips.Concat(mxAddresses).Distinct().Where(ip => Names.SpecialUse(ip) is null).Take(settings.PortScanAddresses).ToList();
        await Task.WhenAll(chosen.Select(async ip =>
        {
            var info = await AddressAsync(ip, targetIsAddress ? "The address asked about" : "Port scanned", withOwner: false).ConfigureAwait(false);
            if (!Names.CanReach(ip))
            {
                dossier.Change(() => dossier.Ports.Add(new PortReport { Ip = ip, Skipped = "Not scanned: this computer has no IPv6 connection." }));
                return;
            }
            if (!targetIsAddress && !settings.ScanCdnAddresses && info.ProviderKind is ServiceKind.Cdn or ServiceKind.Security)
            {
                var skipped = new PortReport { Ip = ip, Skipped = $"Not scanned: it's a {info.Provider} address, so its ports answer for {info.Provider}, not this site. Settings can turn this on." };
                dossier.Change(() => dossier.Ports.Add(skipped));
                return;
            }
            var report = await scanner.ScanAsync(ip, ports, cancel).ConfigureAwait(false);
            dossier.Change(() => dossier.Ports.Add(report));
            await FollowOpenPortsAsync(report, ip, name).ConfigureAwait(false);
        })).ConfigureAwait(false);
    }

    /// <summary>TLS found on other ports gets a quick test too, and a mail port found on an address asked about gets asked what it is.</summary>
    private async Task FollowOpenPortsAsync(PortReport report, string ip, string? name)
    {
        if (!settings.Tls) return;
        var done = dossier.Read(() => dossier.Tls.Where(t => t.Ip == ip).Select(t => t.Port).ToHashSet());
        var candidates = report.Open.Where(p => !done.Contains(p.Port) && (p.Tls || StartTls.ForPort(p.Port).Length > 0 && p.Announced)).Take(6);
        await Task.WhenAll(candidates.Select(async port =>
        {
            var tls = await tlsScanner.ScanAsync(name ?? ip, ip, port.Port, name, StartTls.ForPort(port.Port), thorough: false, cancel).ConfigureAwait(false);
            // A plain-text service without STARTTLS is what the port scan already says.
            if (tls.Error is null) AddTls(tls);
        })).ConfigureAwait(false);
    }

    // ---- Mail ------------------------------------------------------------------------------------------------------------

    private async Task MailAsync(string name, string zone)
    {
        // A subdomain with its own mail settings is judged on them; otherwise the domain's own are what's in effect.
        var own = await resolver.MailHostsAsync(name, cancel).ConfigureAwait(false);
        var ownSpf = (await resolver.TextAsync(name, cancel).ConfigureAwait(false)).Exists(SpfCheck.IsSpf);
        var domain = own.Count > 0 || ownSpf || name == zone ? name : zone;
        var mail = new MailReport { Domain = domain };
        dossier.Change(() =>
        {
            dossier.MailDomain = domain;
            dossier.Mail = mail;
        });

        var hosts = domain == name ? own : await resolver.MailHostsAsync(domain, cancel).ConfigureAwait(false);
        mail.NullMx = hosts.Count == 1 && hosts[0].Host is "" or ".";
        var hostTasks = new List<Task>();
        if (!mail.NullMx)
        {
            foreach (var (preference, host) in hosts.Take(10))
            {
                var mx = new MxHost { Host = host, Preference = preference, Service = KnownServices.ForMailHost(host) };
                dossier.Change(() => mail.Mx.Add(mx));
                Relate(host, $"mail host of {domain}", 1);
                hostTasks.Add(MxHostAsync(mx, domain));
            }
        }
        dossier.Change(() =>
        {
            mail.Service = mail.Mx.Select(m => m.Service).FirstOrDefault(s => s is not null);
            if (mail.NullMx) mail.Findings.Add(new Finding(Level.Info, "Mail", $"{domain} says it receives no mail at all (a null MX)."));
            else if (hosts.Count == 0) mail.Findings.Add(new Finding(Level.Notice, "Mail", $"{domain} has no MX records: mail for it goes to its A record, if it has one."));
        });

        var dmarcTask = new DmarcCheck(resolver).CheckAsync(domain, cancel);
        var dkimTask = new DkimCheck(resolver).CheckAsync(domain, settings.DkimSelectors, cancel);
        var spfTask = new SpfCheck(resolver).CheckAsync(domain, cancel);
        var stsTask = new TransportChecks(resolver, http).MtaStsAsync(domain, [.. hosts.Select(h => h.Host)], cancel);
        var dmarc = await dmarcTask.ConfigureAwait(false);
        dossier.Change(() => mail.Dmarc = dmarc);
        foreach (var target in dmarc.AggregateTo.Concat(dmarc.FailureTo).Distinct())
        {
            var at = target.LastIndexOf('@');
            if (at >= 0) Relate(target[(at + 1)..].Split('!')[0], $"receives {domain}'s DMARC reports", 1);
        }
        var bimi = await new BimiCheck(resolver, http).CheckAsync(domain, dmarc, cancel).ConfigureAwait(false);
        dossier.Change(() => mail.Bimi = bimi);
        var dkim = await dkimTask.ConfigureAwait(false);
        dossier.Change(() => mail.Dkim = dkim);
        var sts = await stsTask.ConfigureAwait(false);
        dossier.Change(() => mail.MtaSts = sts);
        var spf = await spfTask.ConfigureAwait(false);
        dossier.Change(() => mail.Spf = spf);
        foreach (var node in Flatten(spf.Root))
        {
            if (node.Mechanism == "include" && node.Domain is { } included) Relate(included, $"in {domain}'s SPF record", 1);
        }

        await Task.WhenAll(hostTasks).ConfigureAwait(false);
        await SpfAddressesAsync(mail, spf).ConfigureAwait(false);
    }

    internal static IEnumerable<SpfNode> Flatten(SpfNode? node)
    {
        if (node is null) yield break;
        yield return node;
        foreach (var child in node.Children)
        {
            foreach (var inner in Flatten(child)) yield return inner;
        }
    }

    private async Task MxHostAsync(MxHost mx, string domain)
    {
        var ips = await resolver.AddressesAsync(mx.Host, cancel).ConfigureAwait(false);
        dossier.Change(() => mx.Addresses.AddRange(ips));
        await Task.WhenAll(ips.Select(ip => AddressAsync(ip, $"Mail host {mx.Host}", withOwner: true))).ConfigureAwait(false);
        if (settings.Blocklists) await CheckBlocklistsAsync(ips).ConfigureAwait(false);
        var first = ips.FirstOrDefault(ip => Names.SpecialUse(ip) is null && Names.CanReach(ip));
        if (first is null) return;
        var smtp = await TransportChecks.SmtpAsync(first, cancel).ConfigureAwait(false);
        dossier.Change(() => mx.Smtp.Add(smtp));
        TlsReport? tls = null;
        if (settings.Tls && smtp.Error is null && smtp.StartTls)
        {
            tls = await tlsScanner.ScanAsync(mx.Host, first, 25, mx.Host, "smtp", thorough: false, cancel).ConfigureAwait(false);
            AddTls(tls);
        }
        var rows = await new TransportChecks(resolver, http).TlsaAsync(mx.Host, tls, cancel).ConfigureAwait(false);
        dossier.Change(() => mx.Tlsa.AddRange(rows));
    }

    /// <summary>Each network in SPF: its addresses (a sample of a big one) get their AS, country and reverse name, and
    /// are checked against the blocklists, within the budget.</summary>
    private async Task SpfAddressesAsync(MailReport mail, SpfReport spf)
    {
        var allowed = spf.Networks.Where(n => n.Allowed).ToList();
        var work = new List<(SpfNetwork Network, List<string> Addresses)>();
        foreach (var network in allowed)
        {
            var sample = Names.SampleAddresses(network.Network, Math.Max(1, settings.AddressesPerNetwork));
            var take = Math.Min(sample.Count, Interlocked.Add(ref mailBudget, 0));
            if (take <= 0) take = 1;
            Interlocked.Add(ref mailBudget, -take);
            work.Add((network, sample.Take(take).ToList()));
        }
        dossier.Change(() =>
        {
            foreach (var (network, list) in work) network.Checked.AddRange(list);
        });
        var everyAddress = work.SelectMany(w => w.Addresses.Select(a => (Address: a, w.Network))).ToList();
        await Task.WhenAll(everyAddress.Select(p => AddressAsync(p.Address, $"SPF {p.Network.Network}", withOwner: false))).ConfigureAwait(false);
        if (settings.Blocklists) await CheckBlocklistsAsync(everyAddress.Select(p => p.Address).Distinct().ToList()).ConfigureAwait(false);

        // Which services the networks come to.
        var names = dossier.Read(() => everyAddress.Select(p => dossier.Addresses.GetValueOrDefault(p.Address)?.Provider).OfType<string>().Distinct().ToList());
        dossier.Change(() =>
        {
            foreach (var name in names)
            {
                if (!spf.Services.Contains(name)) spf.Services.Add(name);
            }
        });
    }

    /// <summary>How long blocklist checks may take in all. A list that only answers through a slow DNS server could
    /// otherwise hold up a lookup for many minutes: what doesn't get checked in time is reported.</summary>
    private static readonly TimeSpan BlocklistTime = TimeSpan.FromSeconds(60);

    private async Task CheckBlocklistsAsync(IReadOnlyList<string> ips)
    {
        lock (blocklistChecked)
        {
            blocklistHealth ??= CheckListsHealthAsync();
        }
        await blocklistHealth.ConfigureAwait(false);
        blocklistClock.Start();
        var report = dossier.Blocklists;
        var todo = new List<string>();
        lock (blocklistChecked)
        {
            foreach (var ip in ips)
            {
                if (Names.SpecialUse(ip) is null && blocklistChecked.Add(ip)) todo.Add(ip);
            }
        }
        await Task.WhenAll(todo.Select(async ip =>
        {
            var left = BlocklistTime - blocklistClock.Elapsed;
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
            limit.CancelAfter(left > TimeSpan.Zero ? left : TimeSpan.Zero);
            var results = await blocklists.CheckAsync(ip, usableLists, limit.Token).ConfigureAwait(false);
            cancel.ThrowIfCancellationRequested();
            dossier.Change(() =>
            {
                report.Results[ip] = results;
                if (results.Exists(r => r.Reason == BlocklistCheck.OutOfTime))
                {
                    report.NotChecked++;
                    report.Findings.RemoveAll(f => f.Text.EndsWith("ran out of time.", StringComparison.Ordinal));
                    report.Findings.Add(new Finding(Level.Notice, "Blocklists", $"Some lists didn't answer for {report.NotChecked} addresses: they ran out of time."));
                }
                SummarizeListings(report);
            });
        })).ConfigureAwait(false);
    }

    /// <summary>One finding for each list, since a big provider's networks can be on one many times over. Only an address
    /// known to be used is a warning: one taken as a sample of a big network may never have sent any mail.</summary>
    private void SummarizeListings(BlocklistReport report)
    {
        const string Area = "Listing";
        report.Findings.RemoveAll(f => f.Area == Area);
        var sampled = dossier.Mail?.Spf?.Networks.Where(n => n.Sampled).SelectMany(n => n.Checked).ToHashSet() ?? [];
        var hits = report.Results.SelectMany(r => r.Value.Where(v => v.Status == BlocklistStatus.Listed).Select(v => (Ip: r.Key, Hit: v)));
        foreach (var group in hits.GroupBy(h => (h.Hit.Zone, h.Hit.Policy)))
        {
            var ips = group.Select(h => h.Ip).Order(StringComparer.Ordinal).ToList();
            var serious = !group.Key.Policy && ips.Exists(ip => !sampled.Contains(ip));
            var who = ips.Count == 1 ? $"{ips[0]} is" : $"{ips.Count} addresses are";
            var such = ips.Count == 1 ? "" : $", such as {ips[0]}";
            var why = group.First().Hit.Reason is { } reason ? $": {reason}" : "";
            var note = !group.Key.Policy && !serious ? " Only sampled addresses, which may never have sent mail." : "";
            report.Findings.Add(new Finding(serious ? Level.Warning : Level.Notice, Area, $"{who} on {group.Key.Zone}{such}{why}.{note}"));
        }
    }

    private async Task CheckListsHealthAsync()
    {
        var enabled = settings.BlocklistEntries.Where(e => e.Enabled && e.Zone.Length > 0).ToList();
        var health = await blocklists.HealthAsync(enabled, cancel).ConfigureAwait(false);
        usableLists = health.Where(h => h.Health.Usable).Select(h => h.Entry).ToList();
        dossier.Change(() =>
        {
            dossier.Blocklists.Lists.AddRange(health.Select(h => h.Health));
            var refused = health.Where(h => !h.Health.Usable).Select(h => h.Entry.Name).ToList();
            if (refused.Count > 0) dossier.Blocklists.Findings.Add(new Finding(Level.Info, "Blocklists", $"{refused.Count} of {health.Count} lists couldn't be used and are left out: {string.Join(", ", refused)}."));
        });
    }

    // ---- Cloudflare -------------------------------------------------------------------------------------------------------

    private async Task CloudflareAsync(string zone)
    {
        var accounts = settings.CloudflareAccounts.Where(a => !string.IsNullOrEmpty(a.Token)).ToList();
        if (accounts.Count == 0) return;
        foreach (var account in accounts)
        {
            try
            {
                var client = new CloudflareClient(http, account.Token!);
                var found = await client.FindZoneAsync(zone, cancel).ConfigureAwait(false);
                if (found is null) continue;
                await client.ReadRecordsAsync(found, cancel).ConfigureAwait(false);
                dossier.Change(() => dossier.Cloudflare.Zones.Add(found));
                await ReadOriginsAsync(found).ConfigureAwait(false);
                return;
            }
            catch (HttpRequestException exception)
            {
                // Only the message, which never holds the token.
                dossier.Change(() => dossier.Cloudflare.Errors.Add($"{account.Name}: {exception.Message}"));
            }
        }
        dossier.Change(() =>
        {
            if (dossier.Cloudflare.Zones.Count == 0) dossier.Cloudflare.Findings.Add(new Finding(Level.Info, "Cloudflare", $"No Cloudflare token here can see {zone}, so only the public DNS was used."));
        });
    }

    /// <summary>Every address in the zone's records is looked up: the proxied ones are where the sites really are.</summary>
    private async Task ReadOriginsAsync(CloudflareZone zone)
    {
        var work = new List<Task>();
        foreach (var record in zone.Records)
        {
            if (record.Type is "A" or "AAAA" && IPAddress.TryParse(record.Content, out var address))
            {
                var ip = Names.Canonical(address);
                var role = record.Proxied ? $"Real address of {record.Name} (behind Cloudflare)" : $"{record.Type} of {record.Name} (Cloudflare, not proxied)";
                work.Add(AddressAsync(ip, role, withOwner: record.Proxied));
            }
            else if (record.Type == "CNAME")
            {
                Relate(record.Content, $"{record.Name} points to it (Cloudflare)", 1);
                if (record.Proxied) work.Add(ResolveCnameOriginAsync(record));
            }
        }
        await Task.WhenAll(work).ConfigureAwait(false);

        // The zone's own names go in with those found elsewhere.
        var names = zone.Records.Where(r => r.Type is "A" or "AAAA" or "CNAME").GroupBy(r => r.Name).Select(g => new Subdomain(g.Key, "Cloudflare", g.Where(r => r.Type != "CNAME").Select(r => r.Content).ToList())).ToList();
        dossier.Change(() =>
        {
            foreach (var name in names)
            {
                if (!dossier.Dns.Subdomains.Exists(s => s.Name == name.Name)) dossier.Dns.Subdomains.Add(name);
            }
        });
    }

    private async Task ResolveCnameOriginAsync(CloudflareRecord record)
    {
        foreach (var ip in await resolver.AddressesAsync(record.Content, cancel).ConfigureAwait(false))
        {
            await AddressAsync(ip, $"Real address of {record.Name}, through {record.Content} (behind Cloudflare)", withOwner: true).ConfigureAwait(false);
        }
    }

    private List<string> OriginAddressesOf(string name)
    {
        var result = new List<string>();
        foreach (var zone in dossier.Cloudflare.Zones)
        {
            foreach (var record in zone.Records.Where(r => r.Proxied && r.Name == name && r.Type is "A" or "AAAA"))
            {
                result.Add(record.Content);
            }
        }
        return result;
    }

    /// <summary>The real server behind Cloudflare, tested directly with the site's name.</summary>
    private async Task OriginTlsAsync(string name)
    {
        if (!settings.Tls) return;
        foreach (var ip in dossier.Read(() => OriginAddressesOf(name)).Take(settings.TlsAddresses))
        {
            var report = await tlsScanner.ScanAsync(name, ip, 443, name, "", thorough: false, cancel).ConfigureAwait(false);
            AddTls(report);
        }
    }

    /// <summary>Whether what's hidden behind Cloudflare is given away by something public.</summary>
    private void CrossCheckCloudflare()
    {
        dossier.Change(() =>
        {
            foreach (var zone in dossier.Cloudflare.Zones)
            {
                var hidden = zone.Records.Where(r => r.Proxied && r.Type is "A" or "AAAA").Select(r => r.Content).ToHashSet();
                foreach (var record in zone.Records.Where(r => !r.Proxied && r.Type is "A" or "AAAA" && hidden.Contains(r.Content)))
                {
                    dossier.Cloudflare.Findings.Add(new Finding(Level.Warning, "Cloudflare", $"{record.Name} isn't proxied and has the same address as a proxied record: it gives away the real server, {record.Content}."));
                }
                if (dossier.Mail is { } mail)
                {
                    foreach (var mx in mail.Mx)
                    {
                        foreach (var ip in mx.Addresses.Where(hidden.Contains))
                        {
                            dossier.Cloudflare.Findings.Add(new Finding(Level.Warning, "Cloudflare", $"The mail host {mx.Host} is on {ip}, the real address of a proxied site: the MX record gives it away."));
                        }
                    }
                    foreach (var network in mail.Spf?.Networks ?? [])
                    {
                        foreach (var ip in hidden.Where(h => Names.NetworkContains(network.Network, h)))
                        {
                            dossier.Cloudflare.Findings.Add(new Finding(Level.Notice, "Cloudflare", $"SPF allows {network.Network}, which holds {ip}, the real address of a proxied site: the record gives it away."));
                        }
                    }
                }
                foreach (var port in dossier.Ports.Where(p => hidden.Contains(p.Ip)))
                {
                    if (port.Open.Exists(o => o.Port is 80 or 443))
                    {
                        dossier.Cloudflare.Findings.Add(new Finding(Level.Notice, "Cloudflare", $"The real server {port.Ip} answers on the web ports directly. Unless it only accepts Cloudflare's addresses, Cloudflare can be bypassed."));
                    }
                }
            }
        });
    }

    // ---- Following what was found --------------------------------------------------------------------------------------

    private void Relate(string name, string reason, int depth)
    {
        var plain = Names.NormalizeName(name);
        if (plain is null || Names.IsAddress(plain)) return;
        var domain = Names.RegistrableDomain(plain);
        if (domain is null || domain == dossier.Target.Registrable) return;
        var entry = related.GetOrAdd(domain, key => new RelatedDomain { Domain = key, Depth = depth });
        dossier.Change(() =>
        {
            if (entry.Reasons.Count < 8 && !entry.Reasons.Contains(reason)) entry.Reasons.Add(reason);
        });
    }

    private async Task FollowRelatedAsync()
    {
        var done = new HashSet<string>(StringComparer.Ordinal);
        for (var depth = 1; depth <= settings.FollowDepth; depth++)
        {
            var round = related.Values.Where(r => r.Depth == depth && !done.Contains(r.Domain)).OrderBy(r => r.Domain, StringComparer.Ordinal).ToList();
            var room = settings.FollowLimit - done.Count;
            if (round.Count > room)
            {
                var left = round.Count - Math.Max(room, 0);
                dossier.Change(() => dossier.Notes.Add(new Finding(Level.Info, "Related", $"{left} more related domains weren't looked at: the limit is {settings.FollowLimit}, and Settings can raise it.")));
                round = round.Take(Math.Max(room, 0)).ToList();
            }
            if (round.Count == 0) continue;
            foreach (var entry in round) done.Add(entry.Domain);
            await Task.WhenAll(round.Select(entry => LookAtAsync(entry, depth))).ConfigureAwait(false);
        }
    }

    private async Task LookAtAsync(RelatedDomain entry, int depth)
    {
        dossier.Change(() => dossier.Related.Add(entry));
        var registration = settings.Registration ? RegistrationAsync(entry.Domain, full: false) : Task.FromResult(new Registration { Domain = entry.Domain });
        var ips = resolver.AddressesAsync(entry.Domain, cancel);
        var servers = resolver.NameServersAsync(entry.Domain, cancel);
        var mail = resolver.MailHostsAsync(entry.Domain, cancel);
        var txt = resolver.TextAsync(entry.Domain, cancel);
        var dmarc = resolver.TextAsync($"_dmarc.{entry.Domain}", cancel);
        await Task.WhenAll(registration, ips, servers, mail, txt, dmarc).ConfigureAwait(false);
        dossier.Change(() =>
        {
            entry.Registration = registration.Result;
            entry.Addresses.AddRange(ips.Result);
            entry.NameServers.AddRange(servers.Result);
            entry.MailHosts.AddRange(mail.Result.Select(m => m.Host));
            entry.Spf = txt.Result.Find(SpfCheck.IsSpf);
            entry.DmarcPolicy = dmarc.Result.Find(t => t.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)) is { } record ? TagList.Parse(record).GetValueOrDefault("p") : null;
        });
        await Task.WhenAll(ips.Result.Take(4).Select(ip => AddressAsync(ip, $"A/AAAA of {entry.Domain}", withOwner: false))).ConfigureAwait(false);
        foreach (var server in servers.Result.Where(s => Names.RegistrableDomain(s) != entry.Domain)) Relate(server, $"name server of {entry.Domain}", depth + 1);
        foreach (var host in mail.Result.Select(m => m.Host).Where(h => Names.RegistrableDomain(h) != entry.Domain)) Relate(host, $"mail host of {entry.Domain}", depth + 1);
    }
}

internal static class PipeExtensions
{
    public static TResult Pipe<T, TResult>(this T value, Func<T, TResult> next) => next(value);
}
