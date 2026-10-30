using System.Net;
using System.Net.Sockets;
using DnsClient;

namespace Strongthium.HostDossier;

/// <summary>
/// Reads a domain's SPF record by RFC 7208 and resolves it all the way down: every include and redirect, every a and
/// mx to its addresses, into the list of networks that may send mail for the domain. The ten-lookup limit is counted
/// and reported, but going past it is carried on with, since what's asked is what the record lists.
/// </summary>
public sealed class SpfCheck(Resolver resolver)
{
    private const int HardLimit = 200;
    private const int RecordLimit = 10;
    private const int VoidLimit = 2;

    public async Task<SpfReport> CheckAsync(string domain, CancellationToken cancel)
    {
        var report = new SpfReport { Domain = domain };
        var root = new SpfNode { Term = $"v=spf1 at {domain}", Mechanism = "record", Domain = domain };
        report.Root = root;
        var record = await ReadRecordAsync(domain, root, report, cancel).ConfigureAwait(false);
        report.Record = root.Record;
        if (record is not null)
        {
            await WalkAsync(record, domain, root, report, [domain], true, $"{domain}", true, cancel).ConfigureAwait(false);
        }
        Judge(report);
        return report;
    }

    private async Task<string?> ReadRecordAsync(string domain, SpfNode node, SpfReport report, CancellationToken cancel)
    {
        var answer = await resolver.QueryAsync(domain, QueryType.TXT, cancel).ConfigureAwait(false);
        if (answer.Outcome == DnsOutcome.Failed)
        {
            node.Error = $"The DNS failed for {domain}: {answer.Error}";
            return null;
        }
        if (answer.Outcome is DnsOutcome.NoSuchName or DnsOutcome.NoData) report.VoidLookups++;
        var records = answer.Of<DnsClient.Protocol.TxtRecord>().Select(r => string.Concat(r.Text)).Where(IsSpf).ToList();
        if (records.Count == 0)
        {
            node.Error = $"{domain} has no SPF record.";
            return null;
        }
        if (records.Count > 1)
        {
            node.Error = $"{domain} has {records.Count} SPF records: that's a permanent error.";
            report.Findings.Add(new Finding(Level.Bad, "SPF", $"{domain} has {records.Count} SPF records. There must be one: receivers treat this as a permanent error."));
        }
        node.Record = records[0];
        return records[0];
    }

    internal static bool IsSpf(string text) =>
        text.Equals("v=spf1", StringComparison.OrdinalIgnoreCase) || text.StartsWith("v=spf1 ", StringComparison.OrdinalIgnoreCase);

    private async Task WalkAsync(string record, string domain, SpfNode parent, SpfReport report, HashSet<string> path, bool passing, string source, bool topLevel, CancellationToken cancel)
    {
        var terms = record.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries).Skip(1).ToList();
        string? redirect = null;
        var sawAll = false;

        foreach (var term in terms)
        {
            var (qualifier, body) = SplitQualifier(term);
            var nameEnd = body.IndexOfAny([':', '/', '=']);
            var mechanism = (nameEnd < 0 ? body : body[..nameEnd]).ToLowerInvariant();
            var isModifier = nameEnd >= 0 && body[nameEnd] == '=';
            if (sawAll && !isModifier)
            {
                parent.Children.Add(new SpfNode { Term = term, Mechanism = mechanism, Qualifier = qualifier, Note = "Ignored: it comes after \"all\"." });
                continue;
            }
            var node = new SpfNode { Term = term, Mechanism = mechanism, Qualifier = qualifier };
            parent.Children.Add(node);
            var allowed = passing && qualifier == SpfQualifier.Pass;

            if (isModifier)
            {
                var value = body[(nameEnd + 1)..];
                if (mechanism == "redirect") redirect = value;
                else if (mechanism == "exp") node.Note = "The explanation given to rejected senders.";
                else node.Note = "An unknown modifier, which is ignored.";
                continue;
            }

            var argument = nameEnd >= 0 && body[nameEnd] == ':' ? body[(nameEnd + 1)..] : null;
            var cidr = nameEnd >= 0 && body[nameEnd] == '/' ? body[nameEnd..] : null;
            switch (mechanism)
            {
                case "all":
                    sawAll = true;
                    if (topLevel) report.AllTerm = term;
                    node.Note = "Everything not matched above.";
                    break;

                case "ip4" or "ip6":
                    if (argument is null || !Names.TryParseNetwork(argument, out var network, out var prefix) || network.AddressFamily != (mechanism == "ip4" ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6))
                    {
                        node.Error = "Not a valid network.";
                        report.Findings.Add(new Finding(Level.Bad, "SPF", $"\"{term}\" in {domain}'s record isn't a valid network: that's a permanent error."));
                        break;
                    }
                    AddNetwork(node, report, Names.FormatNetwork(network, prefix), $"{source} › {term}", allowed);
                    break;

                case "a" or "mx":
                    await AddressMechanismAsync(node, mechanism, argument, cidr, domain, report, $"{source} › {term}", allowed, cancel).ConfigureAwait(false);
                    break;

                case "include":
                    if (argument is null)
                    {
                        node.Error = "include without a domain.";
                        break;
                    }
                    node.DnsLookups = 1;
                    report.DnsLookups++;
                    var included = Expand(argument, domain);
                    if (included is null)
                    {
                        node.Note = "This depends on the sender (it uses a macro), so it can't be listed.";
                        report.Incomplete = true;
                        break;
                    }
                    node.Domain = included;
                    if (KnownServices.ForSpfInclude(included) is { } service)
                    {
                        node.Note = service;
                        if (!report.Services.Contains(service)) report.Services.Add(service);
                    }
                    await FollowAsync(node, included, report, path, allowed, $"{source} › include:{included}", topLevel: false, cancel).ConfigureAwait(false);
                    break;

                case "exists":
                    node.DnsLookups = 1;
                    report.DnsLookups++;
                    node.Note = "Asks the DNS about each sender, usually to allow networks too long to list.";
                    report.Incomplete = true;
                    break;

                case "ptr":
                    node.DnsLookups = 1;
                    report.DnsLookups++;
                    node.Note = "Allows any address whose reverse name is in this domain: there's no list to show.";
                    report.Incomplete = true;
                    report.Findings.Add(new Finding(Level.Warning, "SPF", $"{domain} uses \"ptr\", which RFC 7208 says not to, and which is slow and unreliable."));
                    break;

                default:
                    node.Error = "An unknown mechanism.";
                    report.Findings.Add(new Finding(Level.Bad, "SPF", $"\"{term}\" in {domain}'s record isn't an SPF mechanism: that's a permanent error."));
                    break;
            }
        }

        // A redirect takes over only if nothing here decided with "all".
        if (redirect is not null && !sawAll)
        {
            var target = Expand(redirect, domain);
            var node = parent.Children.FindLast(n => n.Mechanism == "redirect");
            if (node is not null)
            {
                node.DnsLookups = 1;
                report.DnsLookups++;
                if (target is null)
                {
                    node.Note = "This depends on the sender (it uses a macro), so it can't be listed.";
                    report.Incomplete = true;
                }
                else
                {
                    node.Domain = target;
                    await FollowAsync(node, target, report, path, passing, $"{source} › redirect={target}", topLevel, cancel).ConfigureAwait(false);
                }
            }
        }
    }

    private async Task FollowAsync(SpfNode node, string target, SpfReport report, HashSet<string> path, bool passing, string source, bool topLevel, CancellationToken cancel)
    {
        if (path.Contains(target))
        {
            node.Error = "It leads back to a record already being read: a loop.";
            report.Findings.Add(new Finding(Level.Bad, "SPF", $"The record includes itself, through {target}."));
            return;
        }
        if (report.DnsLookups > HardLimit)
        {
            node.Error = "Not followed: far past any limit.";
            report.Incomplete = true;
            return;
        }
        var record = await ReadRecordAsync(target, node, report, cancel).ConfigureAwait(false);
        if (record is null)
        {
            report.Findings.Add(new Finding(Level.Bad, "SPF", node.Error is { } error ? $"\"{node.Term}\": {error}" : $"\"{node.Term}\" has nothing there."));
            return;
        }
        var deeper = new HashSet<string>(path) { target };
        await WalkAsync(record, target, node, report, deeper, passing, source, topLevel, cancel).ConfigureAwait(false);
    }

    private async Task AddressMechanismAsync(SpfNode node, string mechanism, string? argument, string? cidr, string domain, SpfReport report, string source, bool allowed, CancellationToken cancel)
    {
        node.DnsLookups = 1;
        report.DnsLookups++;
        var spec = argument;
        // a:example.com/24//64, with the lengths after the domain.
        if (spec is not null)
        {
            var slash = spec.IndexOf('/');
            if (slash >= 0)
            {
                cidr = spec[slash..];
                spec = spec[..slash];
            }
        }
        var target = spec is null ? domain : Expand(spec, domain);
        if (target is null)
        {
            node.Note = "This depends on the sender (it uses a macro), so it can't be listed.";
            report.Incomplete = true;
            return;
        }
        node.Domain = target;
        var (v4, v6) = ReadLengths(cidr);

        var hosts = new List<string>();
        if (mechanism == "mx")
        {
            var mail = await resolver.MailHostsAsync(target, cancel).ConfigureAwait(false);
            hosts.AddRange(mail.Select(m => m.Host));
            if (hosts.Count > RecordLimit)
            {
                report.Findings.Add(new Finding(Level.Bad, "SPF", $"\"{node.Term}\" comes to {hosts.Count} mail hosts, above the limit of {RecordLimit}: a permanent error."));
            }
        }
        else
        {
            hosts.Add(target);
        }
        if (hosts.Count == 0) report.VoidLookups++;
        var any = false;
        foreach (var host in hosts)
        {
            foreach (var address in await resolver.AddressesAsync(host, cancel).ConfigureAwait(false))
            {
                any = true;
                var length = IPAddress.Parse(address).AddressFamily == AddressFamily.InterNetwork ? v4 : v6;
                Names.TryParseNetwork($"{address}/{length}", out var network, out var prefix);
                AddNetwork(node, report, Names.FormatNetwork(network, prefix), $"{source} ({host})", allowed);
            }
        }
        if (!any)
        {
            report.VoidLookups += hosts.Count > 0 ? 1 : 0;
            node.Note = $"{target} has no addresses to allow.";
        }
    }

    private static (int V4, int V6) ReadLengths(string? cidr)
    {
        var v4 = 32;
        var v6 = 128;
        if (string.IsNullOrEmpty(cidr)) return (v4, v6);
        var parts = cidr.Split("//");
        if (parts[0].StartsWith('/') && int.TryParse(parts[0][1..], out var four) && four is >= 0 and <= 32) v4 = four;
        if (parts.Length > 1 && int.TryParse(parts[1], out var six) && six is >= 0 and <= 128) v6 = six;
        return (v4, v6);
    }

    private static void AddNetwork(SpfNode node, SpfReport report, string network, string source, bool allowed)
    {
        node.Networks.Add(network);
        // The first mention decides, as it does for a receiver reading the record in order.
        if (report.Networks.Exists(n => n.Network == network)) return;
        report.Networks.Add(new SpfNetwork { Network = network, Source = source, AddressCount = Names.AddressCount(network), Allowed = allowed });
    }

    private static (SpfQualifier, string) SplitQualifier(string term) => term[0] switch
    {
        '+' => (SpfQualifier.Pass, term[1..]),
        '-' => (SpfQualifier.Fail, term[1..]),
        '~' => (SpfQualifier.SoftFail, term[1..]),
        '?' => (SpfQualifier.Neutral, term[1..]),
        _ => (SpfQualifier.Pass, term),
    };

    /// <summary>A target with macros in it: those that come from the domain itself can be filled in; those that come
    /// from the sender (<c>%{i}</c>, <c>%{s}</c>, <c>%{l}</c>) mean there's no one answer, and null is returned.</summary>
    internal static string? Expand(string spec, string domain)
    {
        if (!spec.Contains('%')) return Names.NormalizeName(spec);
        var text = spec.Replace("%%", "%").Replace("%_", " ").Replace("%-", "%20");
        var output = new System.Text.StringBuilder();
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] == '%' && i + 1 < text.Length && text[i + 1] == '{')
            {
                var close = text.IndexOf('}', i);
                if (close < 0) return null;
                var macro = text[(i + 2)..close].ToLowerInvariant();
                if (macro is not ("d" or "o")) return null;
                output.Append(domain);
                i = close;
            }
            else
            {
                output.Append(text[i]);
            }
        }
        return Names.NormalizeName(output.ToString());
    }

    private static void Judge(SpfReport report)
    {
        void Say(Level level, string text) => report.Findings.Add(new Finding(level, "SPF", text));
        if (report.Record is null)
        {
            Say(Level.Warning, $"{report.Domain} has no SPF record: receivers can't tell who may send its mail.");
            return;
        }
        switch (report.AllTerm)
        {
            case null: Say(Level.Warning, "The record doesn't end in \"all\": mail from anywhere else gets a neutral result."); break;
            case var term when term.StartsWith("+", StringComparison.Ordinal) || term.Equals("all", StringComparison.OrdinalIgnoreCase): Say(Level.Bad, "The record ends in \"+all\": anyone in the world may send mail as this domain."); break;
            case var term when term.StartsWith("?", StringComparison.Ordinal): Say(Level.Warning, "The record ends in \"?all\": mail from anywhere else is treated as neutral, which protects nothing."); break;
            case var term when term.StartsWith("~", StringComparison.Ordinal): Say(Level.Notice, "The record ends in \"~all\": mail from elsewhere is marked as suspect, not refused. With DMARC enforcing, that's a common choice."); break;
            default: Say(Level.Good, "The record ends in \"-all\": mail from anywhere else fails."); break;
        }
        if (report.DnsLookups > 10) Say(Level.Bad, $"It takes {report.DnsLookups} DNS lookups; the limit is 10. Receivers stop at the limit and treat it as a permanent error, so SPF fails for all this domain's mail.");
        else if (report.DnsLookups >= 8) Say(Level.Notice, $"It takes {report.DnsLookups} of the 10 DNS lookups allowed.");
        else Say(Level.Info, $"It takes {report.DnsLookups} of the 10 DNS lookups allowed.");
        if (report.VoidLookups > VoidLimit) Say(Level.Warning, $"{report.VoidLookups} lookups come back with nothing; RFC 7208 suggests stopping after {VoidLimit}, and some receivers do.");
        var total = report.Networks.Where(n => n.Allowed).Sum(n => n.Network.Contains(':') ? 0 : n.AddressCount);
        if (total > 16_777_216) Say(Level.Warning, $"It allows {total / 1_000_000:0} million IPv4 addresses: anyone else on those networks can send as this domain.");
        foreach (var network in report.Networks.Where(n => n.Allowed && !n.Network.Contains(':') && n.AddressCount >= 65536 && !n.Source.Contains("include:", StringComparison.Ordinal)))
        {
            Say(Level.Warning, $"It directly allows {network.Network}, {network.AddressCount:N0} addresses.");
        }
        if (report.Incomplete) Say(Level.Info, "Some of it can only be resolved for one particular sender, so the list of networks isn't everything it allows.");
    }
}
