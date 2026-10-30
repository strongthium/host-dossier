using System.Security.Cryptography;
using System.Text;

namespace Strongthium.HostDossier;

/// <summary>The hello a probe sends. Which protocols and ciphers a server accepts can only be told by asking for each
/// one: .NET (and Windows under it) won't offer old ones, so the hello is written here byte by byte.</summary>
internal sealed record HelloOptions
{
    public const ushort Ssl3 = 0x0300, Tls10 = 0x0301, Tls11 = 0x0302, Tls12 = 0x0303, Tls13 = 0x0304;

    public required ushort Version { get; init; }
    public required IReadOnlyList<ushort> Ciphers { get; init; }
    public string? Sni { get; init; }
    public IReadOnlyList<ushort>? Groups { get; init; }
    /// <summary>Offer no key share in TLS 1.3, so that the server has to name the group it wants.</summary>
    public bool EmptyKeyShare { get; init; }
    public bool Deflate { get; init; }
    public bool FallbackScsv { get; init; }
    public bool Heartbeat { get; init; }
}

internal enum ReplyKind { Hello, Alert, Closed, NotTls, TimedOut }

/// <summary>What came back: the server's hello and what the handshake showed in clear before encryption started.</summary>
internal sealed class TlsReply
{
    public ReplyKind Kind { get; set; }
    public byte Alert { get; set; }
    public ushort Version { get; set; }
    public ushort Cipher { get; set; }
    public byte Compression { get; set; }
    public bool HelloRetry { get; set; }
    public Dictionary<ushort, byte[]> Extensions { get; } = [];
    public List<byte[]> Certificates { get; } = [];
    public byte[]? StapledOcsp { get; set; }
    public int? DhBits { get; set; }
    public ushort? Curve { get; set; }
    public ushort? SelectedGroup { get; set; }
}

internal static class TlsWire
{
    public const ushort ExtensionRenegotiation = 0xFF01, ExtensionTicket = 35, ExtensionMasterSecret = 23, ExtensionHeartbeat = 15, ExtensionStatus = 5, ExtensionVersions = 43, ExtensionKeyShare = 51;

    private static readonly byte[] RetryRandom = Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    private static readonly ushort[] SignatureAlgorithms =
    [
        0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080A, 0x080B, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0201, 0x0203, 0x0202, 0x0101,
    ];

    /// <summary>The curves and groups offered unless a probe asks for particular ones.</summary>
    private static readonly ushort[] DefaultGroups = [0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x0100, 0x0101, 0x0102, 0x0016, 0x0015, 0x0013, 0x001A, 0x001B, 0x001C];

    public static byte[] ClientHello(HelloOptions options)
    {
        var random = RandomNumberGenerator.GetBytes(32);
        var isTls13 = options.Version == HelloOptions.Tls13;
        var clientVersion = isTls13 ? HelloOptions.Tls12 : options.Version;

        var body = new ByteWriter();
        body.U16(clientVersion);
        body.Bytes(random);
        // A session id is what real TLS 1.3 clients send, and some middleboxes want it.
        var session = isTls13 ? RandomNumberGenerator.GetBytes(32) : [];
        body.U8((byte)session.Length);
        body.Bytes(session);
        var ciphers = options.FallbackScsv ? [.. options.Ciphers, 0x5600] : options.Ciphers;
        body.U16((ushort)(ciphers.Count * 2));
        foreach (var cipher in ciphers) body.U16(cipher);
        if (options.Deflate)
        {
            body.U8(2);
            body.U8(1);
            body.U8(0);
        }
        else
        {
            body.U8(1);
            body.U8(0);
        }
        if (options.Version != HelloOptions.Ssl3) body.Block16(Extensions(options, isTls13));

        var hello = new ByteWriter();
        hello.U8(1);
        hello.U24(body.Length);
        hello.Bytes(body.ToArray());

        var record = new ByteWriter();
        record.U8(22);
        record.U16(options.Version == HelloOptions.Ssl3 ? HelloOptions.Ssl3 : HelloOptions.Tls10);
        record.U16((ushort)hello.Length);
        record.Bytes(hello.ToArray());
        return record.ToArray();
    }

    private static byte[] Extensions(HelloOptions options, bool isTls13)
    {
        var extensions = new ByteWriter();
        if (!string.IsNullOrEmpty(options.Sni))
        {
            var name = Encoding.ASCII.GetBytes(options.Sni);
            var list = new ByteWriter();
            list.U8(0);
            list.U16((ushort)name.Length);
            list.Bytes(name);
            var server = new ByteWriter();
            server.Block16(list.ToArray());
            extensions.Extension(0, server.ToArray());
        }
        // status_request, asking for a stapled OCSP answer.
        extensions.Extension(ExtensionStatus, [1, 0, 0, 0, 0]);
        var groups = options.Groups ?? DefaultGroups;
        var groupList = new ByteWriter();
        foreach (var group in groups) groupList.U16(group);
        var groupsBlock = new ByteWriter();
        groupsBlock.Block16(groupList.ToArray());
        extensions.Extension(10, groupsBlock.ToArray());
        extensions.Extension(11, [1, 0]);
        var signatures = new ByteWriter();
        foreach (var algorithm in SignatureAlgorithms) signatures.U16(algorithm);
        var signaturesBlock = new ByteWriter();
        signaturesBlock.Block16(signatures.ToArray());
        extensions.Extension(13, signaturesBlock.ToArray());
        if (options.Heartbeat) extensions.Extension(ExtensionHeartbeat, [1]);
        extensions.Extension(ExtensionMasterSecret, []);
        extensions.Extension(ExtensionTicket, []);
        extensions.Extension(ExtensionRenegotiation, [0]);
        if (isTls13)
        {
            extensions.Extension(ExtensionVersions, [2, 0x03, 0x04]);
            extensions.Extension(45, [1, 1]);
            var shares = new ByteWriter();
            if (!options.EmptyKeyShare)
            {
                // A random 32-byte X25519 value is a valid key share: the handshake never gets as far as using it.
                shares.U16(0x001D);
                shares.U16(32);
                shares.Bytes(RandomNumberGenerator.GetBytes(32));
            }
            var sharesBlock = new ByteWriter();
            sharesBlock.Block16(shares.ToArray());
            extensions.Extension(ExtensionKeyShare, sharesBlock.ToArray());
        }
        return extensions.ToArray();
    }

    /// <summary>Reads the server's records until it has said everything it says in clear.</summary>
    public static async Task<TlsReply> ReadReplyAsync(Stream stream, CancellationToken cancel)
    {
        var reply = new TlsReply { Kind = ReplyKind.Closed };
        var handshake = new List<byte>();
        var total = 0;
        var header = new byte[5];
        try
        {
            while (total < 512 * 1024)
            {
                if (!await FillAsync(stream, header, cancel).ConfigureAwait(false)) return reply;
                var type = header[0];
                if (type is not (20 or 21 or 22 or 23) || header[1] != 3 || header[2] > 4)
                {
                    if (reply.Kind != ReplyKind.Hello) reply.Kind = ReplyKind.NotTls;
                    return reply;
                }
                var length = (header[3] << 8) | header[4];
                var payload = new byte[length];
                if (!await FillAsync(stream, payload, cancel).ConfigureAwait(false)) return reply;
                total += length;
                switch (type)
                {
                    case 21:
                        if (reply.Kind != ReplyKind.Hello && payload.Length >= 2)
                        {
                            reply.Kind = ReplyKind.Alert;
                            reply.Alert = payload[1];
                        }
                        return reply;
                    case 23:
                        return reply;
                    case 22:
                        handshake.AddRange(payload);
                        if (ReadMessages(handshake, reply)) return reply;
                        break;
                }
            }
        }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
        {
            if (reply.Kind != ReplyKind.Hello) reply.Kind = ReplyKind.TimedOut;
        }
        catch (IOException)
        {
            // The server hung up, which is how many of them refuse.
        }
        return reply;
    }

    private static async Task<bool> FillAsync(Stream stream, byte[] buffer, CancellationToken cancel)
    {
        var filled = 0;
        while (filled < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(filled), cancel).ConfigureAwait(false);
            if (read == 0) return false;
            filled += read;
        }
        return true;
    }

    /// <summary>Takes whole messages off the front of the buffer. True when there's nothing more worth waiting for.</summary>
    private static bool ReadMessages(List<byte> buffer, TlsReply reply)
    {
        while (buffer.Count >= 4)
        {
            var length = (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
            if (buffer.Count < 4 + length) return false;
            var type = buffer[0];
            var message = buffer.GetRange(4, length).ToArray();
            buffer.RemoveRange(0, 4 + length);
            switch (type)
            {
                case 2:
                    ParseServerHello(message, reply);
                    // After a TLS 1.3 hello everything is encrypted.
                    if (reply.Version == HelloOptions.Tls13 || reply.HelloRetry) return true;
                    break;
                case 11:
                    ParseCertificates(message, reply);
                    break;
                case 12:
                    ParseKeyExchange(message, reply);
                    break;
                case 14:
                    return true;
                case 22:
                    if (message.Length > 4 && message[0] == 1) reply.StapledOcsp = message[4..];
                    break;
            }
        }
        return false;
    }

    internal static void ParseServerHello(byte[] message, TlsReply reply)
    {
        if (message.Length < 38) return;
        reply.Kind = ReplyKind.Hello;
        reply.Version = (ushort)((message[0] << 8) | message[1]);
        reply.HelloRetry = message.AsSpan(2, 32).SequenceEqual(RetryRandom);
        var position = 34;
        position += 1 + message[position];
        if (position + 3 > message.Length) return;
        reply.Cipher = (ushort)((message[position] << 8) | message[position + 1]);
        reply.Compression = message[position + 2];
        position += 3;
        if (position + 2 > message.Length) return;
        var end = Math.Min(message.Length, position + 2 + ((message[position] << 8) | message[position + 1]));
        position += 2;
        while (position + 4 <= end)
        {
            var type = (ushort)((message[position] << 8) | message[position + 1]);
            var length = (message[position + 2] << 8) | message[position + 3];
            position += 4;
            if (position + length > end) break;
            reply.Extensions[type] = message[position..(position + length)];
            position += length;
        }
        if (reply.Extensions.TryGetValue(ExtensionVersions, out var version) && version.Length == 2)
        {
            reply.Version = (ushort)((version[0] << 8) | version[1]);
        }
        if (reply.Extensions.TryGetValue(ExtensionKeyShare, out var share) && share.Length >= 2)
        {
            reply.SelectedGroup = (ushort)((share[0] << 8) | share[1]);
        }
    }

    private static void ParseCertificates(byte[] message, TlsReply reply)
    {
        if (message.Length < 3) return;
        var position = 3;
        while (position + 3 <= message.Length)
        {
            var length = (message[position] << 16) | (message[position + 1] << 8) | message[position + 2];
            position += 3;
            if (position + length > message.Length) break;
            reply.Certificates.Add(message[position..(position + length)]);
            position += length;
        }
    }

    private static void ParseKeyExchange(byte[] message, TlsReply reply)
    {
        var cipher = CipherSuites.Find(reply.Cipher);
        if (cipher.KeyExchange.StartsWith("ECDH", StringComparison.Ordinal))
        {
            if (message.Length >= 3 && message[0] == 3) reply.Curve = (ushort)((message[1] << 8) | message[2]);
        }
        else if (cipher.KeyExchange.StartsWith("DH", StringComparison.Ordinal) && message.Length >= 3)
        {
            var length = (message[0] << 8) | message[1];
            var position = 2;
            while (length > 0 && position < message.Length && message[position] == 0)
            {
                position++;
                length--;
            }
            var bits = length * 8;
            if (position < message.Length && length > 0)
            {
                var top = message[position];
                while (bits > 0 && (top & 0x80) == 0)
                {
                    top <<= 1;
                    bits--;
                }
            }
            reply.DhBits = bits;
        }
    }

    /// <summary>An SSL 2.0 hello, in its own format. A server that still speaks it answers in that format too.</summary>
    public static byte[] Ssl2ClientHello()
    {
        // The seven SSL 2.0 ciphers, three bytes each.
        byte[] ciphers = [0x07, 0x00, 0xC0, 0x05, 0x00, 0x80, 0x03, 0x00, 0x80, 0x01, 0x00, 0x80, 0x08, 0x00, 0x80, 0x06, 0x00, 0x40, 0x04, 0x00, 0x80];
        var challenge = RandomNumberGenerator.GetBytes(16);
        var body = new ByteWriter();
        body.U8(1);
        body.U16(0x0002);
        body.U16((ushort)ciphers.Length);
        body.U16(0);
        body.U16((ushort)challenge.Length);
        body.Bytes(ciphers);
        body.Bytes(challenge);
        var record = new ByteWriter();
        record.U16((ushort)(0x8000 | body.Length));
        record.Bytes(body.ToArray());
        return record.ToArray();
    }

    public static string AlertName(byte alert) => alert switch
    {
        10 => "unexpected message",
        40 => "handshake failure",
        42 => "bad certificate",
        47 => "illegal parameter",
        50 => "decode error",
        70 => "protocol version",
        71 => "insufficient security",
        80 => "internal error",
        86 => "inappropriate fallback",
        109 => "missing extension",
        112 => "unrecognized name",
        _ => $"alert {alert}",
    };
}

/// <summary>Big-endian bytes, the way TLS writes everything.</summary>
internal sealed class ByteWriter
{
    private readonly MemoryStream stream = new();

    public int Length => (int)stream.Length;
    public void U8(byte value) => stream.WriteByte(value);

    public void U16(ushort value)
    {
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    public void U24(int value)
    {
        stream.WriteByte((byte)(value >> 16));
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    public void Bytes(ReadOnlySpan<byte> bytes) => stream.Write(bytes);

    public void Block16(ReadOnlySpan<byte> bytes)
    {
        U16((ushort)bytes.Length);
        Bytes(bytes);
    }

    public void Extension(ushort type, ReadOnlySpan<byte> data)
    {
        U16(type);
        Block16(data);
    }

    public byte[] ToArray() => stream.ToArray();
}
