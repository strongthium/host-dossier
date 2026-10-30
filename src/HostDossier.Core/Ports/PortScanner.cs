using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Strongthium.HostDossier;

/// <summary>The ports scanned unless the settings say otherwise, and what's usually on them.</summary>
public static class PortCatalog
{
    public const string DefaultList =
        "21,22,23,25,53,80,81,88,110,111,113,119,123,135,139,143,161,179,389,443,445,465,500,514,515,543,548,554,587,631,636,853,873,902,989,990,993,995," +
        "1025,1080,1194,1433,1521,1701,1723,1883,2049,2052,2082,2083,2086,2087,2095,2096,2181,2222,2375,2376,2483,2484,2525,3000,3128,3268,3306,3389,3478,3690,4190,4443,4500,4848," +
        "5000,5060,5061,5222,5269,5432,5601,5672,5900,5984,5985,5986,6379,6443,6667,7001,7443,8000,8008,8080,8081,8088,8181,8443,8888,9000,9042,9090,9092,9100,9200,9443,10000,11211,15672,25565,27017";

    public static string NameOf(int port) => port switch
    {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP", 53 => "DNS", 80 or 81 or 8000 or 8008 or 8080 or 8081 or 8088 or 8181 or 8888 => "HTTP", 88 => "Kerberos",
        110 => "POP3", 111 => "RPC portmapper", 113 => "Ident", 119 => "NNTP", 123 => "NTP", 135 => "Windows RPC", 139 => "NetBIOS", 143 => "IMAP", 161 => "SNMP", 179 => "BGP",
        389 => "LDAP", 443 or 4443 or 7443 or 8443 or 9443 => "HTTPS", 445 => "SMB", 465 => "SMTPS", 500 => "IKE", 514 => "Syslog", 515 => "LPD", 543 => "Kerberos login", 548 => "AFP", 554 => "RTSP", 587 => "SMTP submission",
        631 => "IPP", 636 => "LDAPS", 853 => "DNS over TLS", 873 => "rsync", 902 => "VMware", 989 or 990 => "FTPS", 993 => "IMAPS", 995 => "POP3S",
        1025 => "NFS or RPC", 1080 => "SOCKS", 1194 => "OpenVPN", 1433 => "SQL Server", 1521 => "Oracle", 1701 => "L2TP", 1723 => "PPTP", 1883 => "MQTT", 2049 => "NFS",
        2052 or 2082 or 2086 or 2095 => "cPanel (HTTP)", 2083 or 2087 or 2096 => "cPanel (HTTPS)", 2181 => "ZooKeeper", 2222 => "SSH (alternate)", 2375 => "Docker", 2376 => "Docker (TLS)", 2483 or 2484 => "Oracle", 2525 => "SMTP (alternate)",
        3000 => "HTTP (development)", 3128 => "Squid proxy", 3268 => "LDAP global catalog", 3306 => "MySQL", 3389 => "Remote Desktop", 3478 => "STUN/TURN", 3690 => "Subversion", 4190 => "ManageSieve", 4500 => "IPsec NAT", 4848 => "GlassFish",
        5000 => "HTTP (development)", 5060 => "SIP", 5061 => "SIP (TLS)", 5222 => "XMPP client", 5269 => "XMPP server", 5432 => "PostgreSQL", 5601 => "Kibana", 5672 => "AMQP", 5900 => "VNC", 5984 => "CouchDB", 5985 => "WinRM", 5986 => "WinRM (TLS)",
        6379 => "Redis", 6443 => "Kubernetes API", 6667 => "IRC", 7001 => "WebLogic", 9000 => "HTTP or PHP-FPM", 9042 => "Cassandra", 9090 => "HTTP (admin)", 9092 => "Kafka", 9100 => "Printer", 9200 => "Elasticsearch", 10000 => "Webmin", 11211 => "Memcached", 15672 => "RabbitMQ admin", 25565 => "Minecraft", 27017 => "MongoDB",
        _ => "Unknown",
    };

    /// <summary>Reads "22,80,8000-8010": what's not a port is left out, and the list is capped at 65535 by its nature.</summary>
    public static List<int> Parse(string list)
    {
        var ports = new SortedSet<int>();
        foreach (var part in list.Split([',', ' ', ';', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries))
        {
            var dash = part.IndexOf('-');
            if (dash > 0)
            {
                if (int.TryParse(part[..dash], out var from) && int.TryParse(part[(dash + 1)..], out var to) && from >= 1 && to <= 65535 && from <= to)
                {
                    for (var port = from; port <= to; port++) ports.Add(port);
                }
            }
            else if (int.TryParse(part, out var port) && port is >= 1 and <= 65535)
            {
                ports.Add(port);
            }
        }
        return [.. ports];
    }
}

/// <summary>
/// Which TCP ports answer, by connecting to each, and what's there: whatever the service says about itself first,
/// or says when asked in its own language. It's an ordinary connection, and what's reported as announced is what the
/// service said; otherwise the name is only what usually runs on that port.
/// </summary>
public sealed partial class PortScanner(int concurrency = 48, int timeoutMs = 2500)
{
    // Windows tries a refused connection again for about two seconds before reporting it, so a shorter wait
    // than that would call closed ports filtered.
    private const int BannerWaitMs = 1500;

    public async Task<PortReport> ScanAsync(string ip, IReadOnlyList<int> ports, CancellationToken cancel)
    {
        var report = new PortReport { Ip = ip, Scanned = ports.Count };
        var address = IPAddress.Parse(ip);
        using var gate = new SemaphoreSlim(concurrency);
        var closed = 0;
        var filtered = 0;
        var open = new List<OpenPort>();
        await Task.WhenAll(ports.Select(async port =>
        {
            await gate.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                var result = await ProbeAsync(address, port, cancel).ConfigureAwait(false);
                switch (result.State)
                {
                    case State.Closed: Interlocked.Increment(ref closed); break;
                    case State.Filtered: Interlocked.Increment(ref filtered); break;
                    default:
                        lock (open) open.Add(result.Port!);
                        break;
                }
            }
            finally
            {
                gate.Release();
            }
        })).ConfigureAwait(false);
        report.Closed = closed;
        report.Filtered = filtered;
        report.Open.AddRange(open.OrderBy(p => p.Port));
        Judge(report);
        return report;
    }

    private static void Judge(PortReport report)
    {
        void Say(Level level, string text) => report.Findings.Add(new Finding(level, "Ports", $"{report.Ip}: {text}"));
        foreach (var port in report.Open)
        {
            switch (port.Port)
            {
                case 23: Say(Level.Bad, "Telnet is open: everything on it, passwords included, travels unencrypted."); break;
                case 21 when !port.Tls: Say(Level.Warning, "FTP is open: unless it requires TLS, passwords travel unencrypted."); break;
                case 445 or 139: Say(Level.Bad, $"{port.Service} (port {port.Port}) is reachable from the internet, which it should almost never be."); break;
                case 3389: Say(Level.Warning, "Remote Desktop is reachable from the internet: a constant target for password guessing."); break;
                case 5900: Say(Level.Warning, "VNC is reachable from the internet."); break;
                case 3306 or 5432 or 1433 or 1521 or 27017 or 9042 or 5984: Say(Level.Warning, $"The database {port.Service} (port {port.Port}) is reachable from the internet."); break;
                case 6379 or 11211 or 9200 or 2375 or 2181: Say(Level.Bad, $"{port.Service} (port {port.Port}) is reachable from the internet; by default it has no password."); break;
            }
        }
    }

    private enum State { Open, Closed, Filtered }

    private sealed record Result(State State, OpenPort? Port);

    private async Task<Result> ProbeAsync(IPAddress address, int port, CancellationToken cancel)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(timeoutMs);
        using var client = new TcpClient(address.AddressFamily) { NoDelay = true };
        try
        {
            await client.ConnectAsync(address, port, timeout.Token).ConfigureAwait(false);
        }
        catch (SocketException exception)
        {
            return new Result(exception.SocketErrorCode == SocketError.ConnectionRefused ? State.Closed : State.Filtered, null);
        }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
        {
            return new Result(State.Filtered, null);
        }
        return new Result(State.Open, await IdentifyAsync(client.GetStream(), port, cancel).ConfigureAwait(false));
    }

    private static async Task<OpenPort> IdentifyAsync(NetworkStream stream, int port, CancellationToken cancel)
    {
        var usual = PortCatalog.NameOf(port);
        try
        {
            // Many services speak first.
            var greeting = await ReadAsync(stream, BannerWaitMs, cancel).ConfigureAwait(false);
            if (greeting.Length == 0)
            {
                // Then ask, in what this port usually speaks.
                var question = QuestionFor(port);
                if (question is not null)
                {
                    await stream.WriteAsync(question, cancel).ConfigureAwait(false);
                    greeting = await ReadAsync(stream, BannerWaitMs, cancel).ConfigureAwait(false);
                }
            }
            if (greeting.Length == 0) return new OpenPort(port, usual, null, null, null, false, false);
            return Fingerprint(port, greeting);
        }
        catch (Exception exception) when (exception is IOException or SocketException or OperationCanceledException && !cancel.IsCancellationRequested)
        {
            return new OpenPort(port, usual, null, null, null, false, false);
        }
    }

    private static async Task<byte[]> ReadAsync(NetworkStream stream, int waitMs, CancellationToken cancel)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(waitMs);
        var buffer = new byte[4096];
        try
        {
            var read = await stream.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            return buffer[..read];
        }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
        {
            return [];
        }
    }

    private static readonly byte[] HttpQuestion = Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\r\nUser-Agent: host-dossier\r\n\r\n");

    private static byte[]? QuestionFor(int port) => port switch
    {
        // A TLS hello for what's usually TLS, which also tells TLS apart from anything else.
        443 or 465 or 636 or 853 or 989 or 990 or 993 or 995 or 2083 or 2087 or 2096 or 2376 or 4443 or 5061 or 5986 or 6443 or 7443 or 8443 or 9443 =>
            TlsWire.ClientHello(new HelloOptions { Version = HelloOptions.Tls12, Ciphers = CipherSuites.Common }),
        6379 => Encoding.ASCII.GetBytes("PING\r\n"),
        11211 => Encoding.ASCII.GetBytes("version\r\n"),
        // PostgreSQL's request to start TLS: it answers S or N.
        5432 => [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F],
        // A Remote Desktop connection request.
        3389 => [0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00],
        21 or 22 or 23 or 25 or 110 or 143 or 587 or 3306 or 5900 => null,
        _ => HttpQuestion,
    };

    internal static OpenPort Fingerprint(int port, byte[] data)
    {
        var usual = PortCatalog.NameOf(port);
        var text = Encoding.Latin1.GetString(data);
        var firstLine = Printable(text.Split('\n')[0]);

        // TLS: a handshake or alert record.
        if (data.Length >= 3 && data[0] is 0x15 or 0x16 && data[1] == 3)
        {
            return new OpenPort(port, usual, null, null, "TLS", true, true);
        }
        if (text.StartsWith("SSH-", StringComparison.Ordinal))
        {
            var match = SshBanner().Match(firstLine);
            var product = match.Success ? match.Groups[1].Value : null;
            var version = match.Success && match.Groups[2].Success ? match.Groups[2].Value : null;
            return new OpenPort(port, "SSH", product, version, firstLine, true, false);
        }
        if (text.StartsWith("HTTP/", StringComparison.Ordinal))
        {
            var server = HttpServer().Match(text);
            var product = server.Success ? Printable(server.Groups[1].Value) : null;
            return new OpenPort(port, port is 3128 or 8888 && product?.Contains("squid", StringComparison.OrdinalIgnoreCase) == true ? "HTTP proxy" : "HTTP", product, null, firstLine, true, false);
        }
        if (text.StartsWith("RFB ", StringComparison.Ordinal)) return new OpenPort(port, "VNC", null, firstLine[4..], firstLine, true, false);
        if (text.StartsWith("+PONG", StringComparison.Ordinal)) return new OpenPort(port, "Redis", "Redis", null, "PONG without a password", true, false);
        if (text.StartsWith("-NOAUTH", StringComparison.Ordinal) || text.StartsWith("-DENIED", StringComparison.Ordinal)) return new OpenPort(port, "Redis", "Redis", null, firstLine, true, false);
        if (text.StartsWith("VERSION ", StringComparison.Ordinal)) return new OpenPort(port, "Memcached", "Memcached", firstLine[8..], firstLine, true, false);
        if (port == 5432 && data.Length == 1 && data[0] is (byte)'S' or (byte)'N') return new OpenPort(port, "PostgreSQL", "PostgreSQL", null, data[0] == 'S' ? "TLS offered" : "No TLS", true, data[0] == 'S');
        if (port == 3389 && data.Length >= 4 && data[0] == 3 && data[1] == 0) return new OpenPort(port, "Remote Desktop", "Microsoft Remote Desktop", null, null, true, false);

        // MySQL's greeting: a length, a packet number, the protocol (10) and the version, zero-terminated.
        if (data.Length > 6 && data[4] == 10 && data.AsSpan(5).IndexOf((byte)0) is var end and > 0)
        {
            var version = Encoding.ASCII.GetString(data, 5, end);
            return new OpenPort(port, "MySQL", version.Contains("MariaDB", StringComparison.OrdinalIgnoreCase) ? "MariaDB" : "MySQL", version, version, true, false);
        }

        // Lines that start with a number: SMTP, FTP. Or +OK and * OK: POP3, IMAP.
        if (firstLine.StartsWith("220", StringComparison.Ordinal))
        {
            var isSmtp = firstLine.Contains("SMTP", StringComparison.OrdinalIgnoreCase) || port is 25 or 465 or 587 or 2525;
            var isFtp = firstLine.Contains("FTP", StringComparison.OrdinalIgnoreCase) || port is 21;
            var service = isSmtp && !isFtp ? "SMTP" : isFtp ? "FTP" : usual;
            return new OpenPort(port, service, ProductIn(firstLine), null, firstLine, true, false);
        }
        if (firstLine.StartsWith("+OK", StringComparison.Ordinal)) return new OpenPort(port, "POP3", ProductIn(firstLine), null, firstLine, true, false);
        if (firstLine.StartsWith("* OK", StringComparison.Ordinal)) return new OpenPort(port, "IMAP", ProductIn(firstLine), null, firstLine, true, false);

        var readable = Printable(text);
        return new OpenPort(port, usual, null, null, readable.Length >= 4 ? readable[..Math.Min(readable.Length, 200)] : $"{data.Length} bytes of binary", readable.Length >= 4, false);
    }

    private static string? ProductIn(string line)
    {
        foreach (var product in (string[])["Postfix", "Exim", "Sendmail", "Microsoft ESMTP", "Exchange", "Haraka", "qmail", "OpenSMTPD", "Dovecot", "Courier", "Cyrus", "vsFTPd", "ProFTPD", "Pure-FTPd", "FileZilla", "Mimecast", "Google", "Outlook", "Proton", "Amazon SES"])
        {
            if (line.Contains(product, StringComparison.OrdinalIgnoreCase)) return product;
        }
        return null;
    }

    private static string Printable(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            if (c is >= ' ' and < (char)127) builder.Append(c);
        }
        return builder.ToString().Trim();
    }

    [GeneratedRegex(@"^SSH-[\d.]+-([A-Za-z-]+)[_-]?([\w.]+)?", RegexOptions.CultureInvariant)]
    private static partial Regex SshBanner();

    [GeneratedRegex(@"^Server:\s*(.+?)\r?$", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HttpServer();
}
