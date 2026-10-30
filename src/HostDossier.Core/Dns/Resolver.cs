using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using DnsClient;
using DnsClient.Protocol;

namespace Strongthium.HostDossier;

public enum DnsOutcome { Answered, NoData, NoSuchName, Failed }

/// <summary>A DNS answer: its records, and whether the name exists at all, which SPF, DKIM and the blocklists all
/// care about.</summary>
public sealed record DnsAnswer(DnsOutcome Outcome, IReadOnlyList<DnsResourceRecord> Records, bool Authenticated, string? Error)
{
    public IEnumerable<T> Of<T>() where T : DnsResourceRecord => Records.OfType<T>();
}

/// <summary>Asks the DNS, with one lookup's answers kept so that each name and type is asked only once.</summary>
public sealed class Resolver
{
    private readonly LookupClient client;
    private readonly ConcurrentDictionary<(string, QueryType), Lazy<Task<DnsAnswer>>> cache = new();
    private readonly SemaphoreSlim gate;

    public string Description { get; }

    public Resolver(IReadOnlyList<string> servers)
    {
        // A home or office DNS server is much less able to take many questions at once than a public one.
        gate = new SemaphoreSlim(servers.Count > 0 ? 32 : 8);
        var addresses = new List<NameServer>();
        foreach (var server in servers)
        {
            if (IPAddress.TryParse(server, out var address)) addresses.Add(new NameServer(address));
            else if (IPEndPoint.TryParse(server, out var endPoint)) addresses.Add(new NameServer(endPoint));
        }
        var chosen = addresses.Count > 0 ? addresses : SystemServers();
        var options = chosen.Count > 0 ? new LookupClientOptions([.. chosen]) : new LookupClientOptions();
        options.UseCache = false;
        options.Timeout = TimeSpan.FromSeconds(3);
        options.Retries = 1;
        options.ThrowDnsErrors = false;
        options.ContinueOnDnsError = true;
        options.UseTcpOnly = false;
        options.UseRandomNameServer = false;
        client = new LookupClient(options);
        Description = addresses.Count > 0
            ? string.Join(", ", servers)
            : "this computer's resolver (" + string.Join(", ", client.NameServers.Select(n => n.Address)) + ")";
    }

    /// <summary>The DNS servers of the adapters that lead to the internet. Windows also lists servers on virtual adapters
    /// and placeholder IPv6 ones that never answer, and asking those first makes every lookup wait for a timeout.</summary>
    private static List<NameServer> SystemServers()
    {
        var servers = new List<NameServer>();
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up || adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            var properties = adapter.GetIPProperties();
            if (properties.GatewayAddresses.Count == 0) continue;
            foreach (var address in properties.DnsAddresses)
            {
                if (address.IsIPv6SiteLocal || address.IsIPv6LinkLocal) continue;
                if (!servers.Exists(s => s.Address == address.ToString())) servers.Add(new NameServer(address));
            }
        }
        return servers;
    }

    public Task<DnsAnswer> QueryAsync(string name, QueryType type, CancellationToken cancel = default) =>
        cache.GetOrAdd((name.ToLowerInvariant(), type), key => new Lazy<Task<DnsAnswer>>(() => AskAsync(key.Item1, key.Item2, cancel))).Value;

    private async Task<DnsAnswer> AskAsync(string name, QueryType type, CancellationToken cancel)
    {
        await gate.WaitAsync(cancel).ConfigureAwait(false);
        try
        {
            var response = await client.QueryAsync(name, type, QueryClass.IN, cancel).ConfigureAwait(false);
            var code = response.Header.ResponseCode;
            if (code == DnsHeaderResponseCode.NotExistentDomain)
            {
                return new DnsAnswer(DnsOutcome.NoSuchName, [], false, null);
            }
            if (response.HasError && code != DnsHeaderResponseCode.NoError)
            {
                return new DnsAnswer(DnsOutcome.Failed, [], false, response.ErrorMessage);
            }
            var answers = response.Answers.ToList();
            return new DnsAnswer(answers.Count > 0 ? DnsOutcome.Answered : DnsOutcome.NoData, answers, response.Header.IsAuthenticData, null);
        }
        catch (DnsResponseException exception)
        {
            return new DnsAnswer(DnsOutcome.Failed, [], false, exception.Message);
        }
        catch (Exception exception) when (exception is SocketException or IOException or ArgumentException or InvalidOperationException)
        {
            return new DnsAnswer(DnsOutcome.Failed, [], false, exception.Message);
        }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
        {
            return new DnsAnswer(DnsOutcome.Failed, [], false, "No answer in time.");
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>A name's addresses, IPv4 first. CNAMEs are followed by the resolver.</summary>
    public async Task<List<string>> AddressesAsync(string name, CancellationToken cancel = default)
    {
        var v4 = QueryAsync(name, QueryType.A, cancel);
        var v6 = QueryAsync(name, QueryType.AAAA, cancel);
        await Task.WhenAll(v4, v6).ConfigureAwait(false);
        var addresses = new List<string>();
        addresses.AddRange(v4.Result.Of<ARecord>().Select(r => Names.Canonical(r.Address)));
        addresses.AddRange(v6.Result.Of<AaaaRecord>().Select(r => Names.Canonical(r.Address)));
        return addresses.Distinct().ToList();
    }

    public async Task<(List<string> Names, bool Failed)> ReverseAsync(string ip, CancellationToken cancel = default)
    {
        var zone = IPAddress.Parse(ip).AddressFamily == AddressFamily.InterNetwork ? "in-addr.arpa" : "ip6.arpa";
        var answer = await QueryAsync($"{Names.ReversedLabels(ip)}.{zone}", QueryType.PTR, cancel).ConfigureAwait(false);
        return (answer.Of<PtrRecord>().Select(r => r.PtrDomainName.Value.TrimEnd('.').ToLowerInvariant()).Distinct().ToList(), answer.Outcome == DnsOutcome.Failed);
    }

    /// <summary>A name's TXT records, each one's strings joined as the standard says they are.</summary>
    public async Task<List<string>> TextAsync(string name, CancellationToken cancel = default)
    {
        var answer = await QueryAsync(name, QueryType.TXT, cancel).ConfigureAwait(false);
        return answer.Of<TxtRecord>().Select(r => string.Concat(r.Text)).ToList();
    }

    public async Task<List<(int Preference, string Host)>> MailHostsAsync(string name, CancellationToken cancel = default)
    {
        var answer = await QueryAsync(name, QueryType.MX, cancel).ConfigureAwait(false);
        return answer.Of<MxRecord>()
            .Select(r => ((int)r.Preference, r.Exchange.Value.TrimEnd('.').ToLowerInvariant()))
            .Distinct().OrderBy(m => m.Item1).ThenBy(m => m.Item2).ToList();
    }

    public async Task<List<string>> NameServersAsync(string name, CancellationToken cancel = default)
    {
        var answer = await QueryAsync(name, QueryType.NS, cancel).ConfigureAwait(false);
        return answer.Of<NsRecord>().Select(r => r.NSDName.Value.TrimEnd('.').ToLowerInvariant()).Distinct().OrderBy(n => n, StringComparer.Ordinal).ToList();
    }
}
