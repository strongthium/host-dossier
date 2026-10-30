using System.Net;
using System.Net.Sockets;
using DnsClient;
using DnsClient.Protocol;

namespace Strongthium.HostDossier;

/// <summary>
/// Checks addresses against DNS blocklists (RFC 5782). Each list is tried first on its test addresses: a list that's
/// shut down can answer "listed" for everything, and one that refuses this computer's resolver answers with an error
/// code that looks like a listing. Neither should be mistaken for a verdict on the address.
/// </summary>
public sealed class BlocklistCheck(IReadOnlyList<Resolver> resolvers)
{
    public const string OutOfTime = "No answer in time.";

    private readonly Dictionary<string, Resolver> chosen = new(StringComparer.Ordinal);

    public static List<BlocklistEntry> DefaultLists() =>
    [
        new() { Zone = "zen.spamhaus.org", Name = "Spamhaus ZEN", Ipv6 = true, Note = "Refuses queries from public resolvers such as 8.8.8.8 and 1.1.1.1" },
        new() { Zone = "bl.spamcop.net", Name = "SpamCop" },
        new() { Zone = "b.barracudacentral.org", Name = "Barracuda", Note = "Needs the resolver's address registered with Barracuda" },
        new() { Zone = "dnsbl-1.uceprotect.net", Name = "UCEPROTECT level 1" },
        new() { Zone = "dnsbl-2.uceprotect.net", Name = "UCEPROTECT level 2", Enabled = false, Note = "Lists whole networks: a listing may have nothing to do with this address" },
        new() { Zone = "psbl.surriel.com", Name = "PSBL" },
        new() { Zone = "dnsbl.dronebl.org", Name = "DroneBL", Ipv6 = true },
        new() { Zone = "bl.mailspike.net", Name = "Mailspike" },
        new() { Zone = "ubl.unsubscore.com", Name = "LashBack", Enabled = false, Note = "Doesn't answer for its test address, so a clean result can't be told from a list out of service" },
        new() { Zone = "all.s5h.net", Name = "s5h" },
        new() { Zone = "dnsbl.spfbl.net", Name = "SPFBL", Ipv6 = true },
        new() { Zone = "rbl.interserver.net", Name = "InterServer" },
        new() { Zone = "bl.blocklist.de", Name = "blocklist.de" },
        new() { Zone = "spam.spamrats.com", Name = "SpamRATS Spam" },
        new() { Zone = "dyna.spamrats.com", Name = "SpamRATS Dyna" },
        new() { Zone = "noptr.spamrats.com", Name = "SpamRATS NoPtr" },
    ];

    /// <summary>Which of the lists can be believed right now.</summary>
    public async Task<List<(BlocklistEntry Entry, BlocklistHealth Health)>> HealthAsync(IEnumerable<BlocklistEntry> lists, CancellationToken cancel)
    {
        return (await Task.WhenAll(lists.Select(async entry => (entry, await HealthOfAsync(entry, cancel).ConfigureAwait(false)))).ConfigureAwait(false)).ToList();
    }

    /// <summary>Tries each resolver until one gets a proper answer: many lists refuse the big public resolvers, and do
    /// answer the computer's own, unless that forwards to one of them.</summary>
    private async Task<BlocklistHealth> HealthOfAsync(BlocklistEntry entry, CancellationToken cancel)
    {
        BlocklistHealth? first = null;
        foreach (var resolver in resolvers)
        {
            var health = await HealthThroughAsync(entry, resolver, cancel).ConfigureAwait(false);
            if (health.Usable)
            {
                lock (chosen) chosen[entry.Zone] = resolver;
                return health;
            }
            first ??= health;
        }
        if (first is null) return new BlocklistHealth(entry.Zone, entry.Name, false, "No DNS server to ask.");
        return resolvers.Count > 1 ? first with { Detail = first.Detail + " This computer's own DNS server didn't get an answer from it either." } : first;
    }

    private static async Task<BlocklistHealth> HealthThroughAsync(BlocklistEntry entry, Resolver resolver, CancellationToken cancel)
    {
        var test = await resolver.QueryAsync($"2.0.0.127.{entry.Zone}", QueryType.A, cancel).ConfigureAwait(false);
        var never = await resolver.QueryAsync($"1.0.0.127.{entry.Zone}", QueryType.A, cancel).ConfigureAwait(false);
        var testCodes = test.Of<ARecord>().Select(r => r.Address.ToString()).ToList();

        if (test.Outcome == DnsOutcome.Failed) return new BlocklistHealth(entry.Zone, entry.Name, false, "No answer: " + test.Error);
        if (testCodes.Exists(IsRefusal)) return new BlocklistHealth(entry.Zone, entry.Name, false, RefusalText(entry, testCodes.Find(IsRefusal)!));
        if (never.Of<ARecord>().Any() && !never.Of<ARecord>().Any(r => IsRefusal(r.Address.ToString())))
        {
            return new BlocklistHealth(entry.Zone, entry.Name, false, "It says everything is listed, even the address that must never be: it's out of service or the resolver is answering for it.");
        }
        if (testCodes.Count == 0)
        {
            return new BlocklistHealth(entry.Zone, entry.Name, false, "It doesn't list its own test address, so a clean result from it would mean nothing.");
        }
        return new BlocklistHealth(entry.Zone, entry.Name, true, "Answering properly.");
    }

    private static bool IsRefusal(string code) => code.StartsWith("127.255.255.", StringComparison.Ordinal);

    private static string RefusalText(BlocklistEntry entry, string code) => code switch
    {
        "127.255.255.254" => "It refuses queries through this DNS server: it blocks public and shared ones.",
        "127.255.255.255" => "It refuses this resolver for sending too many queries.",
        "127.255.255.252" => "It says the query was badly formed.",
        _ => $"It refuses this query ({code}).{(entry.Note is { } note ? " " + note + "." : "")}",
    };

    public async Task<List<BlocklistResult>> CheckAsync(string ip, IEnumerable<BlocklistEntry> lists, CancellationToken cancel)
    {
        var isV6 = IPAddress.Parse(ip).AddressFamily == AddressFamily.InterNetworkV6;
        var labels = Names.ReversedLabels(ip);
        var results = await Task.WhenAll(lists.Select(async entry =>
        {
            if (isV6 && !entry.Ipv6) return new BlocklistResult(entry.Zone, BlocklistStatus.NotApplicable, null, "Doesn't list IPv6.");
            Resolver resolver;
            lock (chosen) resolver = chosen.GetValueOrDefault(entry.Zone) ?? resolvers[0];
            var name = $"{labels}.{entry.Zone}";
            DnsAnswer answer;
            try
            {
                answer = await resolver.QueryAsync(name, QueryType.A, cancel).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Out of time for this list: the others' answers still count.
                return new BlocklistResult(entry.Zone, BlocklistStatus.Failed, null, OutOfTime);
            }
            if (answer.Outcome == DnsOutcome.Failed) return new BlocklistResult(entry.Zone, BlocklistStatus.Failed, null, answer.Error);
            var codes = answer.Of<ARecord>().Select(r => r.Address.ToString()).ToList();
            if (codes.Count == 0) return new BlocklistResult(entry.Zone, BlocklistStatus.Clean, null, null);
            if (codes.Exists(IsRefusal)) return new BlocklistResult(entry.Zone, BlocklistStatus.Refused, string.Join(", ", codes), "The list refused the query.");
            // Anything outside 127/8 isn't a list's answer: it's a resolver that answers for names that don't exist.
            if (!codes.Exists(c => c.StartsWith("127.", StringComparison.Ordinal))) return new BlocklistResult(entry.Zone, BlocklistStatus.Failed, string.Join(", ", codes), "Not a blocklist's answer: the resolver may be rewriting it.");
            string? reason;
            try
            {
                reason = (await resolver.TextAsync(name, cancel).ConfigureAwait(false)).FirstOrDefault();
            }
            catch (OperationCanceledException)
            {
                reason = null;
            }
            return new BlocklistResult(entry.Zone, BlocklistStatus.Listed, string.Join(", ", codes), Meaning(entry.Zone, codes) ?? reason, IsPolicy(entry.Zone, codes));
        })).ConfigureAwait(false);
        return [.. results];
    }

    /// <summary>Whether every code only says what kind of address this is. Such a listing is expected of an address that
    /// doesn't send mail, which a sample of a big network mostly won't.</summary>
    internal static bool IsPolicy(string zone, IReadOnlyCollection<string> codes) => zone switch
    {
        "zen.spamhaus.org" => codes.All(c => c is "127.0.0.10" or "127.0.0.11"),
        "dnsbl.spfbl.net" => codes.All(c => c == "127.0.0.4"),
        _ => false,
    };

    /// <summary>What the codes of the most used list stand for, which says whether a listing is about abuse at all.</summary>
    internal static string? Meaning(string zone, IEnumerable<string> codes)
    {
        if (zone == "dnsbl.spfbl.net" && codes.Contains("127.0.0.4")) return "no mail service seen at this address, or a residential one (a policy, not a sign of abuse)";
        if (zone != "zen.spamhaus.org") return null;
        return string.Join("; ", codes.Select(code => code switch
        {
            "127.0.0.2" => "SBL: a known spam source",
            "127.0.0.3" => "CSS: a low-reputation sender",
            "127.0.0.4" or "127.0.0.5" or "127.0.0.6" or "127.0.0.7" => "XBL: an infected or exploited machine",
            "127.0.0.9" => "DROP: a hijacked or criminal network",
            "127.0.0.10" or "127.0.0.11" => "PBL: an end-user network that shouldn't send mail directly (a policy, not a sign of abuse)",
            _ => code,
        }).Distinct());
    }
}
