using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Strongthium.HostDossier.Tests;

public class TlsWireTests
{
    [Theory]
    [InlineData(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "AES GCM", 128, "Strong")]
    [InlineData(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "AES CBC", 128, "Acceptable")]
    [InlineData(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", "AES GCM", 128, "Weak")]
    [InlineData(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "3DES CBC", 112, "Weak")]
    [InlineData(0x0005, "TLS_RSA_WITH_RC4_128_SHA", "RSA", "RC4", 128, "Insecure")]
    [InlineData(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RSA (export)", "RC4", 40, "Insecure")]
    [InlineData(0x0001, "TLS_RSA_WITH_NULL_MD5", "RSA", "None", 0, "Insecure")]
    [InlineData(0x1301, "TLS_AES_128_GCM_SHA256", "ECDHE/DHE", "AES GCM", 128, "Strong")]
    [InlineData(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ChaCha20-Poly1305", 256, "Strong")]
    public void Ciphers_are_read_from_the_registry(ushort id, string name, string exchange, string encryption, int bits, string strength)
    {
        var cipher = CipherSuites.Find(id);
        Assert.Equal(name, cipher.Name);
        Assert.Equal(exchange, cipher.KeyExchange);
        Assert.Equal(encryption, cipher.Encryption);
        Assert.Equal(bits, cipher.Bits);
        Assert.Equal(strength, cipher.Strength);
    }

    [Fact]
    public void Anonymous_key_exchange_is_insecure_and_has_no_forward_secrecy()
    {
        var cipher = CipherSuites.Describe(0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256");
        Assert.Equal(CipherSuites.Insecure, cipher.Strength);
        Assert.False(cipher.ForwardSecret);
    }

    [Fact]
    public void Older_protocols_are_not_offered_what_they_do_not_know()
    {
        Assert.DoesNotContain(CipherSuites.ForOlder, id => CipherSuites.Find(id).Aead);
        Assert.Contains((ushort)0xC02F, CipherSuites.ForTls12);
        Assert.DoesNotContain((ushort)0x1301, CipherSuites.ForTls12);
        Assert.DoesNotContain(CipherSuites.ForTls12, id => CipherSuites.Find(id).KeyExchange.Contains("PSK"));
    }

    [Fact]
    public void A_hello_says_what_it_should()
    {
        var hello = TlsWire.ClientHello(new HelloOptions { Version = HelloOptions.Tls12, Ciphers = [0xC02F, 0x009C], Sni = "example.com" });
        Assert.Equal(22, hello[0]); // Handshake.
        Assert.Equal(1, hello[5]); // ClientHello.
        Assert.Equal(hello.Length - 5, (hello[3] << 8) | hello[4]);
        Assert.Equal(0x03, hello[9]);
        Assert.Equal(0x03, hello[10]);
        Assert.Contains("example.com"u8.ToArray()[0], hello);
        Assert.True(hello.AsSpan().IndexOf("example.com"u8) > 0);
    }

    [Fact]
    public void Ssl3_hello_has_no_extensions()
    {
        var hello = TlsWire.ClientHello(new HelloOptions { Version = HelloOptions.Ssl3, Ciphers = [0x000A] });
        // Header 5 + handshake header 4 + version 2 + random 32 + session 1 + cipher length 2 + cipher 2 + compression 2.
        Assert.Equal(5 + 4 + 2 + 32 + 1 + 2 + 2 + 2, hello.Length);
    }

    [Fact]
    public async Task A_server_hello_is_read_from_its_records()
    {
        // A TLS 1.2 ServerHello with the renegotiation extension, split across two records, then ServerHelloDone.
        var extensions = new byte[] { 0xFF, 0x01, 0x00, 0x01, 0x00 };
        var body = new List<byte> { 0x03, 0x03 };
        body.AddRange(new byte[32]);
        body.Add(0);
        body.AddRange([0xC0, 0x2F, 0x00]);
        body.AddRange([0x00, (byte)extensions.Length]);
        body.AddRange(extensions);
        var message = new List<byte> { 2, 0, 0, (byte)body.Count };
        message.AddRange(body);
        message.AddRange([14, 0, 0, 0]);
        var bytes = message.ToArray();
        var split = bytes.Length / 2;
        var wire = new MemoryStream();
        foreach (var part in new[] { bytes[..split], bytes[split..] })
        {
            wire.Write([22, 3, 3, 0, (byte)part.Length]);
            wire.Write(part);
        }
        wire.Position = 0;

        var reply = await TlsWire.ReadReplyAsync(wire, TestContext.Current.CancellationToken);
        Assert.Equal(ReplyKind.Hello, reply.Kind);
        Assert.Equal(HelloOptions.Tls12, reply.Version);
        Assert.Equal(0xC02F, reply.Cipher);
        Assert.True(reply.Extensions.ContainsKey(TlsWire.ExtensionRenegotiation));
    }

    [Fact]
    public async Task An_alert_is_a_refusal()
    {
        var wire = new MemoryStream([21, 3, 3, 0, 2, 2, 40]);
        var reply = await TlsWire.ReadReplyAsync(wire, TestContext.Current.CancellationToken);
        Assert.Equal(ReplyKind.Alert, reply.Kind);
        Assert.Equal(40, reply.Alert);
    }

    [Fact]
    public async Task What_is_not_tls_is_told_apart()
    {
        var wire = new MemoryStream("HTTP/1.1 400 Bad Request\r\n"u8.ToArray());
        var reply = await TlsWire.ReadReplyAsync(wire, TestContext.Current.CancellationToken);
        Assert.Equal(ReplyKind.NotTls, reply.Kind);
    }

    [Fact]
    public void A_retry_request_gives_the_group_it_wants()
    {
        var body = new List<byte> { 0x03, 0x03 };
        body.AddRange(Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"));
        body.Add(0);
        body.AddRange([0x13, 0x02, 0x00]);
        byte[] extensions = [0x00, 43, 0x00, 0x02, 0x03, 0x04, 0x00, 51, 0x00, 0x02, 0x00, 0x1D];
        body.AddRange([0x00, (byte)extensions.Length]);
        body.AddRange(extensions);
        var reply = new TlsReply();
        TlsWire.ParseServerHello(body.ToArray(), reply);
        Assert.True(reply.HelloRetry);
        Assert.Equal(HelloOptions.Tls13, reply.Version);
        Assert.Equal((ushort)0x001D, reply.SelectedGroup);
    }

    /// <summary>The whole scanner, against a real TLS server on the loopback address that only knows TLS 1.2 and up.</summary>
    [Fact]
    public async Task Scans_a_real_server()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=test.example", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("test.example");
        request.CertificateExtensions.Add(names.Build());
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        using var certificate = X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pfx), null);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var stop = new CancellationTokenSource();
        var server = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(stop.Token); }
                catch (OperationCanceledException) { return; }
                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try
                        {
                            await using var tls = new SslStream(client.GetStream());
                            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, stop.Token);
                        }
                        catch (Exception exception) when (exception is IOException or System.Security.Authentication.AuthenticationException or OperationCanceledException or SocketException)
                        {
                            // The probes hang up after the server's hello, which is what they're for.
                        }
                    }
                });
            }
        }, TestContext.Current.CancellationToken);

        var report = await new TlsScanner().ScanAsync("test.example", "127.0.0.1", port, "test.example", "", thorough: true, TestContext.Current.CancellationToken);
        stop.Cancel();
        listener.Stop();
        await server;

        Assert.Null(report.Error);
        Assert.Contains(report.Protocols, p => p.Supported && p.Name is "TLS 1.2" or "TLS 1.3");
        Assert.DoesNotContain(report.Protocols, p => p.Supported && p.Name is "SSL 2.0" or "SSL 3.0");
        Assert.Contains(report.Protocols.SelectMany(p => p.Ciphers), c => c.ForwardSecret);
        Assert.NotEmpty(report.Chain);
        Assert.Contains("test.example", report.Chain[0].Names);
        Assert.True(report.NameMatches);
        // Self-signed: not trusted, which holds the grade to T.
        Assert.False(report.Trusted);
        Assert.Equal("T", report.Grade);
    }

    [Fact]
    public async Task A_plain_service_is_not_called_tls()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var stop = new CancellationTokenSource();
        var server = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    using var client = await listener.AcceptTcpClientAsync(stop.Token);
                    await client.GetStream().WriteAsync("HTTP/1.1 400 Bad Request\r\n\r\n"u8.ToArray(), stop.Token);
                }
                catch (Exception exception) when (exception is OperationCanceledException or IOException or SocketException)
                {
                    return;
                }
            }
        }, TestContext.Current.CancellationToken);
        var report = await new TlsScanner(replyTimeoutMs: 1500).ScanAsync("127.0.0.1", "127.0.0.1", port, null, "", thorough: true, TestContext.Current.CancellationToken);
        stop.Cancel();
        listener.Stop();
        await server;
        Assert.Equal("This port doesn't speak TLS.", report.Error);
    }
}
