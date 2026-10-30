using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Strongthium.HostDossier;

/// <summary>
/// One address's network, country and reverse name. The AS number, routed prefix and country come from Team Cymru's
/// IP-to-ASN service, asked over DNS: nothing to download, and it's what's routed today. Results are kept per lookup,
/// and a prefix already seen answers for every address in it.
/// </summary>
public sealed class AddressLookup(Resolver resolver, Rdap rdap)
{
    private readonly ConcurrentDictionary<string, Lazy<Task<NetworkFacts?>>> byAddress = new();
    private readonly ConcurrentDictionary<long, Lazy<Task<string?>>> asNames = new();
    private readonly ConcurrentDictionary<string, Lazy<Task<NetworkOwner>>> owners = new();
    private readonly List<NetworkFacts> prefixes = [];

    internal sealed record NetworkFacts(long Asn, string Prefix, string? Country, string? Registry, string? Allocated);

    /// <summary>Fills in a new <see cref="AddressInfo"/>. With <paramref name="withOwner"/> it also asks the regional
    /// registry who the block is assigned to, which is slower and limited, so it's kept for the addresses that matter.</summary>
    public async Task FillAsync(AddressInfo info, bool withOwner, CancellationToken cancel, CancellationToken reverseLimit = default)
    {
        var special = Names.SpecialUse(info.Ip);
        if (special is not null)
        {
            info.Special = special;
            return;
        }
        // The network first: it's quick, and it's there even when the reverse lookup runs out of time.
        var facts = await FactsAsync(info.Ip, cancel).ConfigureAwait(false);
        if (facts is not null)
        {
            info.Asn = facts.Asn;
            info.Prefix = facts.Prefix;
            info.Country = facts.Country;
            info.Registry = facts.Registry;
            info.Allocated = facts.Allocated;
            info.AsName = await AsNameAsync(facts.Asn, cancel).ConfigureAwait(false);
            if (KnownServices.ForNetwork(facts.Asn) is { } service)
            {
                info.Provider = service.Name;
                info.ProviderKind = service.Kind;
            }
        }
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel, reverseLimit);
        try
        {
            var (names, failed) = await resolver.ReverseAsync(info.Ip, limit.Token).ConfigureAwait(false);
            if (failed) info.ReverseNote = "The DNS gave no answer";
            info.ReverseNames.AddRange(names);
            if (names.Count > 0)
            {
                var confirmed = false;
                foreach (var name in names.Take(3))
                {
                    if ((await resolver.AddressesAsync(name, limit.Token).ConfigureAwait(false)).Contains(info.Ip)) confirmed = true;
                }
                info.ForwardConfirmed = confirmed;
            }
        }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
        {
            info.ReverseNote = "No answer in time";
        }
        if (withOwner) await FillOwnerAsync(info, cancel).ConfigureAwait(false);
    }

    /// <summary>
    /// Every routed prefix in a network, with its AS and country, by asking about the network's first address, jumping past
    /// the prefix that answers, and asking again. It takes one question for a network routed as one piece, however big it
    /// is, and so covers all of its addresses. Stops at <paramref name="maxSteps"/>, and says whether it reached the end.
    /// </summary>
    public async Task<(List<NetworkRoute> Routes, bool Complete)> RoutesAsync(string network, CancellationToken cancel, int maxSteps = 64)
    {
        var routes = new List<NetworkRoute>();
        if (!Names.TryGetRange(network, out var first, out var last, out var family)) return (routes, true);
        // An unrouted gap is crossed at the smallest size that's routed on the internet.
        var gap = family == AddressFamily.InterNetwork ? (UInt128)256 : UInt128.One << 80;
        var current = first;
        for (var step = 0; step < maxSteps; step++)
        {
            var ip = Names.AddressAt(current, family);
            var facts = Names.SpecialUse(ip) is null ? await FactsAsync(ip, cancel).ConfigureAwait(false) : null;
            UInt128 next;
            if (facts is not null && Names.TryGetRange(facts.Prefix, out _, out var prefixEnd, out _))
            {
                if (!routes.Exists(r => r.Prefix == facts.Prefix))
                {
                    routes.Add(new NetworkRoute(facts.Prefix, facts.Asn, await AsNameAsync(facts.Asn, cancel).ConfigureAwait(false), facts.Country, KnownServices.ForNetwork(facts.Asn)?.Name));
                }
                if (prefixEnd >= last) return (routes, true);
                next = prefixEnd + 1;
            }
            else
            {
                next = current + gap - current % gap;
                if (next > last || next < current) return (routes, true);
            }
            current = next;
        }
        return (routes, false);
    }

    /// <summary>The block's owner; a block already asked about isn't asked about again.</summary>
    public async Task FillOwnerAsync(AddressInfo info, CancellationToken cancel)
    {
        if (info.Special is not null || info.Owner is not null) return;
        var key = info.Prefix ?? info.Ip;
        info.Owner = await owners.GetOrAdd(key, _ => new Lazy<Task<NetworkOwner>>(() => rdap.AddressAsync(info.Ip, cancel))).Value.ConfigureAwait(false);
    }

    private Task<NetworkFacts?> FactsAsync(string ip, CancellationToken cancel)
    {
        lock (prefixes)
        {
            var known = prefixes.Find(p => Names.NetworkContains(p.Prefix, ip));
            if (known is not null) return Task.FromResult<NetworkFacts?>(known);
        }
        return byAddress.GetOrAdd(ip, _ => new Lazy<Task<NetworkFacts?>>(() => AskAsync(ip, cancel))).Value;
    }

    private async Task<NetworkFacts?> AskAsync(string ip, CancellationToken cancel)
    {
        var zone = IPAddress.Parse(ip).AddressFamily == AddressFamily.InterNetwork ? "origin.asn.cymru.com" : "origin6.asn.cymru.com";
        var texts = await resolver.TextAsync($"{Names.ReversedLabels(ip)}.{zone}", cancel).ConfigureAwait(false);
        // The most specific prefix decides, when several are announced.
        var facts = texts.Select(ParseOrigin).OfType<NetworkFacts>()
            .OrderByDescending(f => int.TryParse(f.Prefix.Split('/').LastOrDefault(), out var length) ? length : 0)
            .FirstOrDefault();
        if (facts is not null)
        {
            lock (prefixes) prefixes.Add(facts);
        }
        return facts;
    }

    /// <summary>"15169 | 8.8.8.0/24 | US | arin | 2023-12-28": several AS numbers come space-separated first.</summary>
    internal static NetworkFacts? ParseOrigin(string text)
    {
        var fields = text.Split('|', StringSplitOptions.TrimEntries);
        if (fields.Length < 3) return null;
        var first = fields[0].Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        if (!long.TryParse(first, NumberStyles.None, CultureInfo.InvariantCulture, out var asn)) return null;
        return new NetworkFacts(asn, fields[1], Blank(fields[2])?.ToUpperInvariant(), fields.Length > 3 ? Blank(fields[3]) : null, fields.Length > 4 ? Blank(fields[4]) : null);
    }

    private Task<string?> AsNameAsync(long asn, CancellationToken cancel) =>
        asNames.GetOrAdd(asn, _ => new Lazy<Task<string?>>(async () =>
        {
            var texts = await resolver.TextAsync($"AS{asn}.asn.cymru.com", cancel).ConfigureAwait(false);
            return texts.Select(ParseAsName).FirstOrDefault(n => n is not null);
        })).Value;

    /// <summary>"15169 | US | arin | 2000-03-30 | GOOGLE, US": the name is the last field, and it ends with a country.</summary>
    internal static string? ParseAsName(string text)
    {
        var fields = text.Split('|', StringSplitOptions.TrimEntries);
        if (fields.Length < 5) return null;
        var name = fields[4];
        var comma = name.LastIndexOf(',');
        if (comma > 0 && name[(comma + 1)..].Trim().Length == 2) name = name[..comma];
        return Blank(name);
    }

    private static string? Blank(string text) => text.Length == 0 || text == "NA" ? null : text;
}
