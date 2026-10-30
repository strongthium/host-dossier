using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Strongthium.HostDossier;

/// <summary>
/// How a domain's mail travels between servers: MTA-STS (the HTTPS-published promise to use TLS), TLS-RPT (where to
/// report failures), what an SMTP server says about itself, and DANE (TLSA records).
/// </summary>
public sealed class TransportChecks(Resolver resolver, HttpClient http)
{
    public async Task<MtaStsReport> MtaStsAsync(string domain, IReadOnlyList<string> mxHosts, CancellationToken cancel)
    {
        var report = new MtaStsReport { Domain = domain };
        void Say(Level level, string text) => report.Findings.Add(new Finding(level, "MTA-STS", text));

        var rpt = await resolver.TextAsync($"_smtp._tls.{domain}", cancel).ConfigureAwait(false);
        report.TlsRpt = rpt.Find(t => t.StartsWith("v=TLSRPTv1", StringComparison.OrdinalIgnoreCase));

        var texts = await resolver.TextAsync($"_mta-sts.{domain}", cancel).ConfigureAwait(false);
        report.Record = texts.Find(t => t.StartsWith("v=STSv1", StringComparison.OrdinalIgnoreCase));
        if (report.Record is null)
        {
            Say(Level.Info, "No MTA-STS: senders aren't told to insist on TLS when delivering here.");
            return report;
        }

        report.PolicyUrl = $"https://mta-sts.{domain}/.well-known/mta-sts.txt";
        string policy;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
            timeout.CancelAfter(TimeSpan.FromSeconds(12));
            policy = await http.GetStringAsync(report.PolicyUrl, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or OperationCanceledException && !cancel.IsCancellationRequested)
        {
            Say(Level.Bad, $"The record is there but the policy can't be fetched from {report.PolicyUrl}: {exception.GetBaseException().Message}");
            return report;
        }

        foreach (var line in policy.Split('\n'))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            var value = line[(colon + 1)..].Trim();
            switch (line[..colon].Trim().ToLowerInvariant())
            {
                case "mode": report.Mode = value.ToLowerInvariant(); break;
                case "mx": report.PolicyMx.Add(value.ToLowerInvariant()); break;
                case "max_age": report.MaxAge = long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var age) ? age : null; break;
            }
        }
        switch (report.Mode)
        {
            case "enforce": Say(Level.Good, "MTA-STS is enforcing: senders must use TLS with a valid certificate."); break;
            case "testing": Say(Level.Notice, "MTA-STS is in testing: failures are reported, not stopped."); break;
            case "none": Say(Level.Notice, "MTA-STS is turned off (mode: none)."); break;
            default: Say(Level.Bad, "The MTA-STS policy has no valid mode."); break;
        }
        foreach (var host in mxHosts)
        {
            if (!report.PolicyMx.Exists(pattern => MatchesPattern(pattern, host)))
            {
                Say(Level.Bad, $"The policy doesn't list {host}, so enforcing senders won't deliver to it.");
            }
        }
        if (report.TlsRpt is null) Say(Level.Notice, "No TLS-RPT record: nobody hears when senders can't use TLS.");
        return report;
    }

    internal static bool MatchesPattern(string pattern, string host) =>
        pattern.StartsWith("*.", StringComparison.Ordinal)
            ? host.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase) && host.IndexOf('.') == host.Length - pattern.Length + 1
            : string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase);

    /// <summary>Connects to port 25, says hello and leaves: the banner and what the server offers.</summary>
    public static async Task<SmtpProbe> SmtpAsync(string ip, CancellationToken cancel)
    {
        var probe = new SmtpProbe { Ip = ip };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            using var client = new TcpClient(IPAddress.Parse(ip).AddressFamily) { NoDelay = true };
            await client.ConnectAsync(IPAddress.Parse(ip), 25, timeout.Token).ConfigureAwait(false);
            var stream = client.GetStream();
            var banner = await StartTls.ExpectAsync(stream, "220", timeout.Token).ConfigureAwait(false);
            probe.Banner = banner[0].Length > 4 ? banner[0][4..] : banner[0];
            await StartTls.SendAsync(stream, "EHLO host-dossier.invalid", timeout.Token).ConfigureAwait(false);
            var lines = await StartTls.ExpectAsync(stream, "250", timeout.Token).ConfigureAwait(false);
            foreach (var line in lines.Skip(1))
            {
                if (line.Length > 4) probe.Capabilities.Add(line[4..].Trim());
            }
            probe.StartTls = probe.Capabilities.Exists(c => c.Equals("STARTTLS", StringComparison.OrdinalIgnoreCase));
            await StartTls.SendAsync(stream, "QUIT", timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
        {
            probe.Error = "No answer on port 25 in time.";
        }
        catch (Exception exception) when (exception is SocketException or IOException)
        {
            probe.Error = exception.Message;
        }
        return probe;
    }

    public async Task<List<TlsaRow>> TlsaAsync(string host, TlsReport? tls, CancellationToken cancel)
    {
        var name = $"_25._tcp.{host}";
        var answer = await resolver.QueryAsync(name, DnsClient.QueryType.TLSA, cancel).ConfigureAwait(false);
        var rows = new List<TlsaRow>();
        foreach (var record in answer.Of<DnsClient.Protocol.TlsaRecord>())
        {
            var data = record.CertificateAssociationDataAsString.ToLowerInvariant();
            rows.Add(new TlsaRow(name, (int)record.CertificateUsage, (int)record.Selector, (int)record.MatchingType, data,
                Compare((int)record.Selector, (int)record.MatchingType, data, tls)));
        }
        return rows;
    }

    /// <summary>Whether a record matches a certificate the server sent. Only SHA-256 can be compared here: the other
    /// matching types are reported without a verdict.</summary>
    internal static bool? Compare(int selector, int matching, string data, TlsReport? tls)
    {
        if (tls is null || tls.Chain.Count == 0 || matching != 1) return null;
        foreach (var certificate in tls.Chain)
        {
            var hash = selector == 0
                ? certificate.Sha256
                : Convert.ToHexString(Convert.FromBase64String(certificate.SpkiSha256)).ToLowerInvariant();
            if (hash == data) return true;
        }
        return false;
    }
}
