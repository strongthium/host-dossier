using System.Globalization;
using System.Text;
using System.Text.Json;
using DnsClient;
using DnsClient.Protocol;

namespace Strongthium.HostDossier;

/// <summary>Every kind of record at a name, DNSSEC, names found under it by trying common ones and by reading the
/// public certificate logs.</summary>
public sealed class DnsCollector(Resolver resolver, HttpClient http)
{
    private const QueryType Https = (QueryType)65;
    private const QueryType Svcb = (QueryType)64;

    private static readonly QueryType[] Types =
    [
        QueryType.A, QueryType.AAAA, QueryType.CNAME, QueryType.NS, QueryType.SOA, QueryType.MX, QueryType.TXT, QueryType.CAA,
        QueryType.DS, QueryType.DNSKEY, QueryType.SRV, QueryType.NAPTR, QueryType.TLSA, QueryType.SSHFP, QueryType.URI, Https, Svcb,
    ];

    /// <summary>Names a domain often has under it. Tried only to find what's there: only what answers is reported.</summary>
    private static readonly string[] CommonNames =
    [
        "www", "mail", "webmail", "smtp", "imap", "pop", "pop3", "mx", "mx1", "mx2", "autodiscover", "autoconfig", "ftp", "sftp",
        "ns", "ns1", "ns2", "ns3", "ns4", "dns", "api", "app", "apps", "admin", "portal", "login", "auth", "sso", "vpn", "remote", "gateway",
        "blog", "shop", "store", "news", "support", "help", "docs", "wiki", "status", "dev", "test", "staging", "beta", "cdn", "static", "assets",
        "media", "img", "images", "git", "gitlab", "jira", "ci", "m", "mobile", "cloud", "db", "sql", "server", "host", "panel", "cpanel", "whm", "plesk", "owa", "exchange",
    ];

    public async Task<IReadOnlyList<DnsRow>> RecordsAsync(string name, Action<string> problem, CancellationToken cancel)
    {
        var answers = await Task.WhenAll(Types.Select(async type => (Type: type, Answer: await resolver.QueryAsync(name, type, cancel).ConfigureAwait(false)))).ConfigureAwait(false);
        var rows = new List<DnsRow>();
        foreach (var (type, answer) in answers)
        {
            if (answer.Outcome == DnsOutcome.Failed)
            {
                problem($"{type} of {name}: {answer.Error}");
                continue;
            }
            foreach (var record in answer.Records)
            {
                // A CNAME comes along with every other type's answer: it's shown once.
                var row = ToRow(record);
                if (row is not null && !rows.Contains(row)) rows.Add(row);
            }
        }
        return rows;
    }

    /// <summary>Whether the zone is signed (a DS at its parent) and whether the resolver checked the signatures.</summary>
    public async Task DnssecAsync(string zone, DnsReport report, CancellationToken cancel)
    {
        var ds = await resolver.QueryAsync(zone, QueryType.DS, cancel).ConfigureAwait(false);
        var soa = await resolver.QueryAsync(zone, QueryType.SOA, cancel).ConfigureAwait(false);
        if (ds.Outcome != DnsOutcome.Failed) report.Signed = ds.Of<DsRecord>().Any();
        if (soa.Outcome != DnsOutcome.Failed) report.ValidatedByResolver = soa.Authenticated;
    }

    /// <summary>Addresses a made-up name gets: a wildcard record, which makes every trial name seem to exist.</summary>
    public async Task<List<string>> WildcardAsync(string zone, CancellationToken cancel)
    {
        var made = "host-dossier-" + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(6)).ToLowerInvariant();
        return await resolver.AddressesAsync($"{made}.{zone}", cancel).ConfigureAwait(false);
    }

    public async Task<List<Subdomain>> CommonNamesAsync(string zone, IReadOnlyCollection<string> wildcard, CancellationToken cancel)
    {
        var found = await Task.WhenAll(CommonNames.Select(async label =>
        {
            var name = $"{label}.{zone}";
            var addresses = await resolver.AddressesAsync(name, cancel).ConfigureAwait(false);
            return (Name: name, Addresses: addresses);
        })).ConfigureAwait(false);
        return found
            .Where(f => f.Addresses.Count > 0 && !(wildcard.Count > 0 && f.Addresses.All(wildcard.Contains)))
            .Select(f => new Subdomain(f.Name, "Common name", f.Addresses))
            .ToList();
    }

    /// <summary>
    /// The names on certificates issued for a domain, from the public Certificate Transparency logs through crt.sh.
    /// Each is checked in the DNS, since the logs also hold names long gone. crt.sh is often busy: failing is reported,
    /// not hidden.
    /// </summary>
    public async Task<(List<Subdomain> Found, string? Note)> CertificateLogsAsync(string zone, IReadOnlyCollection<string> wildcard, CancellationToken cancel)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
            timeout.CancelAfter(TimeSpan.FromSeconds(25));
            using var response = await http.GetAsync($"https://crt.sh/?q=%25.{zone}&output=json&exclude=expired", timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) return ([], $"The certificate logs (crt.sh) answered {(int)response.StatusCode}.");
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: timeout.Token).ConfigureAwait(false);
            foreach (var entry in document.RootElement.EnumerateArray())
            {
                if (!entry.TryGetProperty("name_value", out var value) || value.GetString() is not { } text) continue;
                foreach (var line in text.Split('\n'))
                {
                    var name = Names.NormalizeName(line.Trim().TrimStart('*', '.'));
                    if (name is not null && name != zone && name.EndsWith("." + zone, StringComparison.Ordinal)) names.Add(name);
                }
            }
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or IOException or InvalidOperationException
            || (exception is OperationCanceledException && !cancel.IsCancellationRequested))
        {
            return ([], "The certificate logs (crt.sh) couldn't be read: " + (exception is OperationCanceledException ? "no answer in time." : exception.Message));
        }

        const int limit = 300;
        var note = names.Count > limit ? $"The certificate logs hold {names.Count} names; the first {limit} were checked." : null;
        var checkedNames = await Task.WhenAll(names.Order(StringComparer.Ordinal).Take(limit).Select(async name =>
            (Name: name, Addresses: await resolver.AddressesAsync(name, cancel).ConfigureAwait(false)))).ConfigureAwait(false);
        var found = checkedNames
            .Where(c => c.Addresses.Count > 0 && !(wildcard.Count > 0 && c.Addresses.All(wildcard.Contains)))
            .Select(c => new Subdomain(c.Name, "Certificate log", c.Addresses))
            .ToList();
        return (found, note);
    }

    internal static DnsRow? ToRow(DnsResourceRecord record)
    {
        var name = record.DomainName.Value.TrimEnd('.').ToLowerInvariant();
        var type = record.RecordType.ToString();
        string? value = record switch
        {
            ARecord r => Names.Canonical(r.Address),
            AaaaRecord r => Names.Canonical(r.Address),
            CNameRecord r => Host(r.CanonicalName),
            NsRecord r => Host(r.NSDName),
            PtrRecord r => Host(r.PtrDomainName),
            MxRecord r => $"{r.Preference} {Host(r.Exchange)}",
            TxtRecord r => string.Concat(r.Text),
            SoaRecord r => $"{Host(r.MName)} {Host(r.RName)} serial {r.Serial}, refresh {r.Refresh}, retry {r.Retry}, expire {r.Expire}, minimum {r.Minimum}",
            CaaRecord r => $"{r.Flags} {r.Tag} \"{r.Value}\"",
            SrvRecord r => $"{r.Priority} {r.Weight} {r.Port} {Host(r.Target)}",
            NAPtrRecord r => $"{r.Order} {r.Preference} \"{r.Flags}\" \"{r.Services}\" \"{r.RegularExpression}\" {r.Replacement}",
            DsRecord r => $"key tag {r.KeyTag}, algorithm {r.Algorithm}, digest type {r.DigestType}, {r.DigestAsString}",
            DnsKeyRecord r => $"flags {r.Flags}, algorithm {r.Algorithm}, {r.PublicKey.Count * 8} bits",
            TlsaRecord r => $"{(int)r.CertificateUsage} {(int)r.Selector} {(int)r.MatchingType} {r.CertificateAssociationDataAsString}",
            SshfpRecord r => $"{(int)r.Algorithm} {(int)r.FingerprintType} {r.Fingerprint}",
            UriRecord r => $"{r.Priority} {r.Weight} \"{r.Target}\"",
            UnknownRecord { RecordType: (ResourceRecordType)65 or (ResourceRecordType)64 } r => ServiceBinding(r.Data.ToArray()),
            UnknownRecord r => r.DataAsString,
            RRSigRecord => null,
            _ => record.ToString(),
        };
        if (record is UnknownRecord { RecordType: (ResourceRecordType)65 }) type = "HTTPS";
        else if (record is UnknownRecord { RecordType: (ResourceRecordType)64 }) type = "SVCB";
        return value is null ? null : new DnsRow(name, type, record.TimeToLive, value);
    }

    private static string Host(DnsString name) => name.Value.TrimEnd('.').ToLowerInvariant();

    /// <summary>An HTTPS or SVCB record, RFC 9460: priority, target and its parameters.</summary>
    internal static string ServiceBinding(byte[] data)
    {
        try
        {
            var position = 2;
            var priority = (data[0] << 8) | data[1];
            var target = new StringBuilder();
            while (data[position] != 0)
            {
                var length = data[position++];
                target.Append(Encoding.ASCII.GetString(data, position, length)).Append('.');
                position += length;
            }
            position++;
            var text = new StringBuilder($"{priority} {(target.Length == 0 ? "." : target.ToString())}");
            while (position + 4 <= data.Length)
            {
                var key = (data[position] << 8) | data[position + 1];
                var length = (data[position + 2] << 8) | data[position + 3];
                position += 4;
                var value = data.AsSpan(position, length);
                position += length;
                switch (key)
                {
                    case 1:
                        var protocols = new List<string>();
                        for (var i = 0; i < value.Length;)
                        {
                            protocols.Add(Encoding.ASCII.GetString(value.Slice(i + 1, value[i])));
                            i += value[i] + 1;
                        }
                        text.Append(" alpn=").Append(string.Join(',', protocols));
                        break;
                    case 3:
                        text.Append(" port=").Append(((value[0] << 8) | value[1]).ToString(CultureInfo.InvariantCulture));
                        break;
                    case 4:
                        text.Append(" ipv4hint=").Append(string.Join(',', value.ToArray().Chunk(4).Select(b => new System.Net.IPAddress(b).ToString())));
                        break;
                    case 5:
                        text.Append(" ech=").Append(value.Length).Append(" bytes");
                        break;
                    case 6:
                        text.Append(" ipv6hint=").Append(string.Join(',', value.ToArray().Chunk(16).Select(b => new System.Net.IPAddress(b).ToString())));
                        break;
                    default:
                        text.Append(" key").Append(key).Append('=').Append(Convert.ToHexString(value));
                        break;
                }
            }
            return text.ToString();
        }
        catch (Exception exception) when (exception is ArgumentException or IndexOutOfRangeException)
        {
            return Convert.ToHexString(data);
        }
    }
}
