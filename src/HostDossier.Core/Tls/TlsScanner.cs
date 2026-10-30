using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Strongthium.HostDossier;

/// <summary>
/// Tests a TLS server the way SSL Labs does: each protocol version is asked for by name, then each protocol's ciphers
/// are found by offering them all and taking away the one the server chose until it refuses. Most probes end after
/// the server's hello: they're ordinary hellos and nothing is exploited.
/// </summary>
public sealed class TlsScanner(int connectTimeoutMs = 6000, int replyTimeoutMs = 7000, int parallel = 4)
{
    private readonly SemaphoreSlim gate = new(parallel);

    /// <param name="startTls">"smtp", "imap", "pop3" or "ftp" to upgrade a plain connection first; "" for TLS straight away.</param>
    /// <param name="thorough">Every cipher, every group. Otherwise each protocol's choice and whether a bad cipher is
    /// accepted, in a few connections, which is all a mail server should be asked to bear.</param>
    public async Task<TlsReport> ScanAsync(string host, string ip, int port, string? sni, string startTls, bool thorough, CancellationToken cancel)
    {
        var report = new TlsReport { Host = host, Ip = ip, Port = port, Sni = sni, StartTls = startTls, Thorough = thorough };
        var address = IPAddress.Parse(ip);

        async Task<TlsReply> Probe(HelloOptions options)
        {
            await gate.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                return await ProbeAsync(address, port, startTls, options, cancel).ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
            }
        }

        // Which protocols, TLS 1.3 down to SSL 2.0.
        var tls13 = new ProtocolResult { Name = "TLS 1.3" };
        var tls12 = new ProtocolResult { Name = "TLS 1.2" };
        var tls11 = new ProtocolResult { Name = "TLS 1.1" };
        var tls10 = new ProtocolResult { Name = "TLS 1.0" };
        var ssl3 = new ProtocolResult { Name = "SSL 3.0" };
        var ssl2 = new ProtocolResult { Name = "SSL 2.0" };
        report.Protocols.AddRange([tls13, tls12, tls11, tls10, ssl3, ssl2]);

        var first12 = (TlsReply?)null;
        var probes = await Task.WhenAll(
            Probe(new HelloOptions { Version = HelloOptions.Tls13, Ciphers = CipherSuites.Tls13, Sni = sni }),
            Probe(new HelloOptions { Version = HelloOptions.Tls12, Ciphers = CipherSuites.ForTls12, Sni = sni }),
            Probe(new HelloOptions { Version = HelloOptions.Tls11, Ciphers = CipherSuites.ForOlder, Sni = sni }),
            Probe(new HelloOptions { Version = HelloOptions.Tls10, Ciphers = CipherSuites.ForOlder, Sni = sni }),
            Probe(new HelloOptions { Version = HelloOptions.Ssl3, Ciphers = CipherSuites.ForOlder })).ConfigureAwait(false);

        var results = new[] { (tls13, HelloOptions.Tls13), (tls12, HelloOptions.Tls12), (tls11, HelloOptions.Tls11), (tls10, HelloOptions.Tls10), (ssl3, HelloOptions.Ssl3) };
        for (var i = 0; i < results.Length; i++)
        {
            var (protocol, version) = results[i];
            var reply = probes[i];
            // A long list makes some old servers hang up: asked again with the usual ciphers.
            if (reply.Kind is ReplyKind.Closed or ReplyKind.TimedOut && version is HelloOptions.Tls12 or HelloOptions.Tls11 or HelloOptions.Tls10)
            {
                reply = await Probe(new HelloOptions { Version = version, Ciphers = CipherSuites.Common, Sni = sni }).ConfigureAwait(false);
                probes[i] = reply;
            }
            protocol.Supported = reply.Kind == ReplyKind.Hello && reply.Version == version;
            if (protocol.Supported)
            {
                if (!(version == HelloOptions.Tls13 && reply.HelloRetry && reply.Cipher == 0)) protocol.Ciphers.Add(CipherSuites.Find(reply.Cipher));
                if (version == HelloOptions.Tls12) first12 = reply;
            }
        }
        ssl2.Supported = await Ssl2ProbeAsync(address, port, startTls, cancel).ConfigureAwait(false);

        var supported = report.Protocols.Where(p => p.Supported).ToList();
        if (supported.Count == 0)
        {
            var refused = probes.All(p => p.Kind is ReplyKind.TimedOut or ReplyKind.Closed);
            var notTls = probes.Any(p => p.Kind == ReplyKind.NotTls);
            var alert = probes.FirstOrDefault(p => p.Kind == ReplyKind.Alert);
            report.Error = notTls ? "This port doesn't speak TLS." : alert is not null ? $"The server refused every hello: {TlsWire.AlertName(alert.Alert)}." : refused ? "Nothing answered with TLS on this port." : "The server refused every hello.";
            return report;
        }

        // Which ciphers.
        var firstByProtocol = results.Select((r, i) => (r.Item1, r.Item2, probes[i])).Where(r => r.Item1.Supported).ToList();
        await Task.WhenAll(firstByProtocol.Select(async entry =>
        {
            var (protocol, version, _) = entry;
            if (thorough)
            {
                await EnumerateAsync(protocol, version, sni, Probe, cancel).ConfigureAwait(false);
            }
            else if (version != HelloOptions.Tls13)
            {
                var bad = CipherSuites.Bad(version == HelloOptions.Tls12);
                var reply = await Probe(new HelloOptions { Version = version, Ciphers = bad, Sni = sni }).ConfigureAwait(false);
                if (reply.Kind == ReplyKind.Hello && reply.Version == version && !protocol.Ciphers.Exists(c => c.Id == reply.Cipher)) protocol.Ciphers.Add(CipherSuites.Find(reply.Cipher));
            }
        })).ConfigureAwait(false);

        // Whose choice it is: the same two ciphers offered both ways round.
        var best = supported.Find(p => p.Ciphers.Count >= 2 && p != tls13) ?? supported.Find(p => p.Ciphers.Count >= 2);
        if (best is not null)
        {
            var version = best == tls13 ? HelloOptions.Tls13 : best == tls12 ? HelloOptions.Tls12 : best == tls11 ? HelloOptions.Tls11 : best == tls10 ? HelloOptions.Tls10 : HelloOptions.Ssl3;
            ushort a = best.Ciphers[0].Id, b = best.Ciphers[^1].Id;
            var forward = await Probe(new HelloOptions { Version = version, Ciphers = [a, b], Sni = sni }).ConfigureAwait(false);
            var backward = await Probe(new HelloOptions { Version = version, Ciphers = [b, a], Sni = sni }).ConfigureAwait(false);
            if (forward.Kind == ReplyKind.Hello && backward.Kind == ReplyKind.Hello) report.ServerChoosesCipher = forward.Cipher == backward.Cipher;
        }

        // What the TLS 1.2 hello already said.
        var bestLegacy = first12 ?? firstByProtocol.Where(r => r.Item2 != HelloOptions.Tls13).Select(r => r.Item3).FirstOrDefault();
        if (bestLegacy is not null)
        {
            report.SecureRenegotiation = bestLegacy.Extensions.ContainsKey(TlsWire.ExtensionRenegotiation);
            report.ExtendedMasterSecret = bestLegacy.Extensions.ContainsKey(TlsWire.ExtensionMasterSecret);
            report.SessionTickets = bestLegacy.Extensions.ContainsKey(TlsWire.ExtensionTicket);
            report.OcspStapled = bestLegacy.StapledOcsp is not null;
            var deflate = await Probe(new HelloOptions { Version = bestLegacy.Version, Ciphers = CipherSuites.Common, Sni = sni, Deflate = true }).ConfigureAwait(false);
            report.Compression = deflate.Kind == ReplyKind.Hello && deflate.Compression != 0;
            var beat = await Probe(new HelloOptions { Version = bestLegacy.Version, Ciphers = CipherSuites.Common, Sni = sni, Heartbeat = true }).ConfigureAwait(false);
            report.HeartbeatOffered = beat.Kind == ReplyKind.Hello && beat.Extensions.ContainsKey(TlsWire.ExtensionHeartbeat);
        }

        // Asked for an older version than it knows, with the signal that this is a downgrade, it must refuse.
        var fallbackVersion = supported.Count >= 2 && supported[1] != ssl2 && supported[1] != ssl3
            ? (supported[1] == tls12 ? HelloOptions.Tls12 : supported[1] == tls11 ? HelloOptions.Tls11 : HelloOptions.Tls10)
            : (ushort)0;
        if (fallbackVersion != 0)
        {
            var fallback = await Probe(new HelloOptions { Version = fallbackVersion, Ciphers = CipherSuites.ForTls12, Sni = sni, FallbackScsv = true }).ConfigureAwait(false);
            report.FallbackProtected = fallback.Kind == ReplyKind.Alert && fallback.Alert == 86;
        }

        // Groups, and the size of Diffie-Hellman.
        if (thorough) await GroupsAsync(report, tls13.Supported, tls12.Supported, sni, Probe, cancel).ConfigureAwait(false);
        var dh = supported.Contains(tls12) ? tls12.Ciphers.Find(c => c.KeyExchange == "DHE") : null;
        if (dh is not null)
        {
            var reply = await Probe(new HelloOptions { Version = HelloOptions.Tls12, Ciphers = [dh.Id], Sni = sni }).ConfigureAwait(false);
            if (reply.DhBits is { } bits) report.DhBits = bits.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        // The certificate, as sent in clear to TLS 1.2 or read through a real handshake for TLS 1.3 alone.
        await CertificateAsync(report, address, port, startTls, sni, first12 ?? bestLegacy, Probe, cancel).ConfigureAwait(false);
        TlsGrade.Apply(report);
        return report;
    }

    private async Task EnumerateAsync(ProtocolResult protocol, ushort version, string? sni, Func<HelloOptions, Task<TlsReply>> probe, CancellationToken cancel)
    {
        var offered = (version == HelloOptions.Tls13 ? CipherSuites.Tls13 : version == HelloOptions.Tls12 ? CipherSuites.ForTls12 : CipherSuites.ForOlder).ToList();
        foreach (var known in protocol.Ciphers) offered.Remove(known.Id);
        // The first already found is kept first: for a server that chooses, this is its order.
        for (var round = 0; round < 80 && offered.Count > 0 && !cancel.IsCancellationRequested; round++)
        {
            var reply = await probe(new HelloOptions { Version = version, Ciphers = offered, Sni = sni }).ConfigureAwait(false);
            if (reply.Kind != ReplyKind.Hello || reply.Version != version || !offered.Remove(reply.Cipher)) break;
            protocol.Ciphers.Add(CipherSuites.Find(reply.Cipher));
        }
    }

    private static async Task GroupsAsync(TlsReport report, bool tls13, bool tls12, string? sni, Func<HelloOptions, Task<TlsReply>> probe, CancellationToken cancel)
    {
        if (!tls13 && !tls12) return;
        var found = await Task.WhenAll(CipherSuites.Groups.Select(async group =>
        {
            if (tls13)
            {
                // With no key share offered, a server that knows the group asks for one with it, which says enough.
                var reply = await probe(new HelloOptions { Version = HelloOptions.Tls13, Ciphers = CipherSuites.Tls13, Sni = sni, Groups = [group.Id], EmptyKeyShare = true }).ConfigureAwait(false);
                if (reply.Kind == ReplyKind.Hello && reply.Version == HelloOptions.Tls13 && reply.SelectedGroup == group.Id) return group.Name;
            }
            if (tls12 && group.Id is < 0x0100 or >= 0x0100 and <= 0x0104)
            {
                var ecdhe = CipherSuites.ForTls12.Where(id => CipherSuites.Find(id).KeyExchange == "ECDHE").ToArray();
                var reply = await probe(new HelloOptions { Version = HelloOptions.Tls12, Ciphers = ecdhe, Sni = sni, Groups = [group.Id] }).ConfigureAwait(false);
                if (reply.Kind == ReplyKind.Hello && reply.Curve == group.Id) return group.Name;
            }
            return null;
        })).ConfigureAwait(false);
        report.Groups.AddRange(found.OfType<string>());
    }

    private async Task CertificateAsync(TlsReport report, IPAddress address, int port, string startTls, string? sni, TlsReply? legacy, Func<HelloOptions, Task<TlsReply>> probe, CancellationToken cancel)
    {
        var sent = new List<X509Certificate2>();
        if (legacy is not null)
        {
            foreach (var der in legacy.Certificates)
            {
                try { sent.Add(X509CertificateLoader.LoadCertificate(der)); }
                catch (System.Security.Cryptography.CryptographicException) { }
            }
        }

        // A real handshake gives the certificates under TLS 1.3, and the protocols agreed by ALPN.
        var handshake = await HandshakeAsync(address, port, startTls, sni, ["h2", "http/1.1"], cancel).ConfigureAwait(false);
        if (sent.Count == 0) sent.AddRange(handshake.Certificates);
        if (startTls.Length == 0)
        {
            if (handshake.Protocol is { Length: > 0 } negotiated) report.Alpn.Add(negotiated);
            if (handshake.Protocol == "h2")
            {
                var older = await HandshakeAsync(address, port, startTls, sni, ["http/1.1"], cancel).ConfigureAwait(false);
                if (older.Protocol == "http/1.1") report.Alpn.Add("http/1.1");
            }
        }

        if (sent.Count == 0)
        {
            report.Findings.Add(new Finding(Level.Notice, "TLS", "The server's certificate couldn't be read: " + (handshake.Error ?? "the handshake gave none.")));
            return;
        }
        Certificates.CheckTrust(sent[0], sent, report);
        var isAddressOnly = Names.IsAddress(report.Host);
        report.NameMatches = isAddressOnly ? null : Certificates.Matches(sent[0], report.Host);

        // Whether a client that doesn't name the site still gets this site.
        if (sni is not null)
        {
            var without = await probe(new HelloOptions { Version = legacy?.Version ?? HelloOptions.Tls12, Ciphers = CipherSuites.Common, Sni = null }).ConfigureAwait(false);
            if (without.Kind != ReplyKind.Hello) report.SniRequired = true;
            else if (without.Certificates.Count > 0) report.SniRequired = !without.Certificates[0].AsSpan().SequenceEqual(sent[0].RawData);
        }
    }

    private sealed record Handshake(string? Protocol, List<X509Certificate2> Certificates, string? Error);

    private async Task<Handshake> HandshakeAsync(IPAddress address, int port, string startTls, string? sni, string[] alpn, CancellationToken cancel)
    {
        await gate.WaitAsync(cancel).ConfigureAwait(false);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(connectTimeoutMs + replyTimeoutMs);
        var certificates = new List<X509Certificate2>();
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            await client.ConnectAsync(address, port, timeout.Token).ConfigureAwait(false);
            var stream = client.GetStream();
            await StartTls.UpgradeAsync(stream, startTls, timeout.Token).ConfigureAwait(false);
            await using var tls = new SslStream(stream);
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = sni ?? "",
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                ApplicationProtocols = startTls.Length == 0 ? [.. alpn.Select(p => new SslApplicationProtocol(p))] : null,
                RemoteCertificateValidationCallback = (_, certificate, chain, _) =>
                {
                    if (certificate is not null) certificates.Add(X509CertificateLoader.LoadCertificate(certificate.GetRawCertData()));
                    if (chain is not null)
                    {
                        foreach (var extra in chain.ChainPolicy.ExtraStore) certificates.Add(extra);
                    }
                    return true;
                },
            };
            await tls.AuthenticateAsClientAsync(options, timeout.Token).ConfigureAwait(false);
            return new Handshake(tls.NegotiatedApplicationProtocol.ToString(), certificates, null);
        }
        catch (Exception exception) when (exception is IOException or SocketException or System.Security.Authentication.AuthenticationException or OperationCanceledException && !cancel.IsCancellationRequested)
        {
            return new Handshake(null, certificates, exception.Message);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<TlsReply> ProbeAsync(IPAddress address, int port, string startTls, HelloOptions options, CancellationToken cancel)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(connectTimeoutMs);
        try
        {
            using var client = new TcpClient(address.AddressFamily) { NoDelay = true };
            await client.ConnectAsync(address, port, timeout.Token).ConfigureAwait(false);
            var stream = client.GetStream();
            timeout.CancelAfter(replyTimeoutMs);
            await StartTls.UpgradeAsync(stream, startTls, timeout.Token).ConfigureAwait(false);
            await stream.WriteAsync(TlsWire.ClientHello(options), timeout.Token).ConfigureAwait(false);
            return await TlsWire.ReadReplyAsync(stream, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
        {
            return new TlsReply { Kind = ReplyKind.TimedOut };
        }
        catch (Exception exception) when (exception is SocketException or IOException)
        {
            return new TlsReply { Kind = ReplyKind.Closed };
        }
    }

    private async Task<bool> Ssl2ProbeAsync(IPAddress address, int port, string startTls, CancellationToken cancel)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(connectTimeoutMs);
        await gate.WaitAsync(cancel).ConfigureAwait(false);
        try
        {
            using var client = new TcpClient(address.AddressFamily) { NoDelay = true };
            await client.ConnectAsync(address, port, timeout.Token).ConfigureAwait(false);
            var stream = client.GetStream();
            await StartTls.UpgradeAsync(stream, startTls, timeout.Token).ConfigureAwait(false);
            await stream.WriteAsync(TlsWire.Ssl2ClientHello(), timeout.Token).ConfigureAwait(false);
            var buffer = new byte[11];
            var read = await stream.ReadAtLeastAsync(buffer, 7, throwOnEndOfStream: false, timeout.Token).ConfigureAwait(false);
            // An SSL 2.0 reply: a two-byte length with the top bit set, then message type 4, SERVER-HELLO, and version 0.2.
            return read >= 7 && (buffer[0] & 0x80) != 0 && buffer[2] == 4 && buffer[5] == 0 && buffer[6] == 2;
        }
        catch (Exception exception) when (exception is SocketException or IOException or OperationCanceledException && !cancel.IsCancellationRequested)
        {
            return false;
        }
        finally
        {
            gate.Release();
        }
    }
}

/// <summary>The plain-text exchange that comes before TLS on mail and FTP ports.</summary>
internal static class StartTls
{
    public static string ForPort(int port) => port switch
    {
        25 or 587 or 2525 => "smtp",
        143 => "imap",
        110 => "pop3",
        21 => "ftp",
        _ => "",
    };

    public static async Task UpgradeAsync(Stream stream, string dialect, CancellationToken cancel)
    {
        switch (dialect)
        {
            case "":
                return;
            case "smtp":
                await ExpectAsync(stream, "220", cancel).ConfigureAwait(false);
                await SendAsync(stream, "EHLO host-dossier.invalid", cancel).ConfigureAwait(false);
                await ExpectAsync(stream, "250", cancel).ConfigureAwait(false);
                await SendAsync(stream, "STARTTLS", cancel).ConfigureAwait(false);
                await ExpectAsync(stream, "220", cancel).ConfigureAwait(false);
                return;
            case "imap":
                await ReadLineAsync(stream, cancel).ConfigureAwait(false);
                await SendAsync(stream, "a STARTTLS", cancel).ConfigureAwait(false);
                await ExpectAsync(stream, "a OK", cancel).ConfigureAwait(false);
                return;
            case "pop3":
                await ReadLineAsync(stream, cancel).ConfigureAwait(false);
                await SendAsync(stream, "STLS", cancel).ConfigureAwait(false);
                await ExpectAsync(stream, "+OK", cancel).ConfigureAwait(false);
                return;
            case "ftp":
                await ExpectAsync(stream, "220", cancel).ConfigureAwait(false);
                await SendAsync(stream, "AUTH TLS", cancel).ConfigureAwait(false);
                await ExpectAsync(stream, "234", cancel).ConfigureAwait(false);
                return;
            default:
                throw new ArgumentException("Unknown STARTTLS dialect: " + dialect, nameof(dialect));
        }
    }

    public static Task SendAsync(Stream stream, string line, CancellationToken cancel) =>
        stream.WriteAsync(Encoding.ASCII.GetBytes(line + "\r\n"), cancel).AsTask();

    /// <summary>Reads to the end of a reply, which for SMTP and FTP can be many lines ("250-", then "250 ").</summary>
    public static async Task<List<string>> ExpectAsync(Stream stream, string code, CancellationToken cancel)
    {
        var lines = new List<string>();
        while (true)
        {
            var line = await ReadLineAsync(stream, cancel).ConfigureAwait(false);
            lines.Add(line);
            if (!line.StartsWith(code, StringComparison.Ordinal)) throw new IOException($"Expected {code}, got: {line}");
            if (line.Length <= code.Length || line[code.Length] != '-') return lines;
        }
    }

    public static async Task<string> ReadLineAsync(Stream stream, CancellationToken cancel)
    {
        var line = new StringBuilder();
        var one = new byte[1];
        while (line.Length < 2048)
        {
            if (await stream.ReadAsync(one, cancel).ConfigureAwait(false) == 0)
            {
                if (line.Length == 0) throw new IOException("The connection closed.");
                break;
            }
            if (one[0] == '\n') break;
            if (one[0] != '\r') line.Append((char)one[0]);
        }
        return line.ToString();
    }
}
