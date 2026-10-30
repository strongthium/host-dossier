using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;

namespace Strongthium.HostDossier;

/// <summary>Domain names and addresses: reading what was typed, the registrable part of a name, CIDR arithmetic.</summary>
public static class Names
{
    private static readonly IdnMapping Idn = new() { AllowUnassigned = false, UseStd3AsciiRules = false };

    /// <summary>Reads a domain, an address, a URL or a mail address. Null with a reason when it's none of them.</summary>
    public static Target? ParseTarget(string input, out string? problem)
    {
        problem = null;
        var text = input.Trim();
        if (text.Length == 0)
        {
            problem = "Enter a domain or an IP address.";
            return null;
        }
        var scheme = text.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) text = text[(scheme + 3)..];
        var at = text.LastIndexOf('@');
        if (at >= 0) text = text[(at + 1)..];

        // An address in brackets, or bare: a bare IPv6 address has colons that aren't a port.
        if (text.StartsWith('[') && text.IndexOf(']') is var close and > 0)
        {
            text = text[1..close];
        }
        else if (!IPAddress.TryParse(text, out _))
        {
            var cut = text.IndexOfAny(['/', '?', '#']);
            if (cut >= 0) text = text[..cut];
            var colon = text.LastIndexOf(':');
            if (colon >= 0 && int.TryParse(text[(colon + 1)..], out _)) text = text[..colon];
        }

        if (IPAddress.TryParse(text, out var address))
        {
            return new Target(input.Trim(), TargetKind.Address, Canonical(address), null);
        }
        var name = NormalizeName(text);
        if (name is null || !name.Contains('.'))
        {
            problem = $"\"{input.Trim()}\" isn't a domain or an IP address.";
            return null;
        }
        return new Target(input.Trim(), TargetKind.Domain, name, RegistrableDomain(name));
    }

    /// <summary>A name in ASCII and lower case without its final dot; null when it can't be a host name.</summary>
    public static string? NormalizeName(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var name = text.Trim().TrimEnd('.');
        try
        {
            name = Idn.GetAscii(name);
        }
        catch (ArgumentException)
        {
            return null;
        }
        name = name.ToLowerInvariant();
        if (name.Length is 0 or > 253) return null;
        foreach (var label in name.Split('.'))
        {
            if (label.Length is 0 or > 63) return null;
            foreach (var c in label)
            {
                if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')) return null;
            }
        }
        return name;
    }

    public static string Canonical(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        // An IPv6 address with a scope prints it after a %, which means nothing outside this computer.
        var text = address.ToString();
        var scope = text.IndexOf('%');
        return scope >= 0 ? text[..scope] : text;
    }

    public static bool IsAddress(string text) => IPAddress.TryParse(text, out _);

    private static readonly Lazy<bool> Ipv6Route = new(() =>
    {
        try
        {
            // Connecting a UDP socket sends nothing: it only asks whether there's a route.
            using var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect(IPAddress.Parse("2001:4860:4860::8888"), 53);
            return socket.LocalEndPoint is IPEndPoint { Address: { IsIPv6LinkLocal: false } };
        }
        catch (SocketException)
        {
            return false;
        }
    });

    /// <summary>Whether this computer can reach this kind of address. Without an IPv6 connection, every IPv6 address looks
    /// as if nothing answers, which says nothing about the address.</summary>
    public static bool CanReach(string ip) => !ip.Contains(':') || Ipv6Route.Value;

    /// <summary>The name to look up an address's PTR, or a blocklist's entry, under, without the zone.</summary>
    public static string ReversedLabels(string ip)
    {
        var address = IPAddress.Parse(ip);
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}";
        }
        var nibbles = new char[bytes.Length * 4 - 1];
        for (var i = 0; i < bytes.Length; i++)
        {
            var b = bytes[bytes.Length - 1 - i];
            nibbles[i * 4] = "0123456789abcdef"[b & 15];
            nibbles[i * 4 + 1] = '.';
            nibbles[i * 4 + 2] = "0123456789abcdef"[b >> 4];
            if (i * 4 + 3 < nibbles.Length) nibbles[i * 4 + 3] = '.';
        }
        return new string(nibbles);
    }

    /// <summary>What an address is for, when it isn't an ordinary address on the public internet.</summary>
    public static string? SpecialUse(string ip)
    {
        var address = IPAddress.Parse(ip);
        var b = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return (b[0], b[1], b[2]) switch
            {
                (0, _, _) => "This network (0.0.0.0/8)",
                (10, _, _) => "Private network (10.0.0.0/8)",
                (100, >= 64 and <= 127, _) => "Shared carrier network (100.64.0.0/10)",
                (127, _, _) => "Loopback",
                (169, 254, _) => "Link-local",
                (172, >= 16 and <= 31, _) => "Private network (172.16.0.0/12)",
                (192, 0, 2) => "Documentation (192.0.2.0/24)",
                (192, 168, _) => "Private network (192.168.0.0/16)",
                (198, >= 18 and <= 19, _) => "Benchmarking (198.18.0.0/15)",
                (198, 51, 100) => "Documentation (198.51.100.0/24)",
                (203, 0, 113) => "Documentation (203.0.113.0/24)",
                (>= 224 and <= 239, _, _) => "Multicast",
                (>= 240, _, _) => "Reserved",
                _ => null,
            };
        }
        if (address.Equals(IPAddress.IPv6Loopback)) return "Loopback";
        if (address.Equals(IPAddress.IPv6Any)) return "Unspecified";
        if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return "Link-local";
        if ((b[0] & 0xfe) == 0xfc) return "Private network (fc00::/7)";
        if (b[0] == 0xff) return "Multicast";
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return "Documentation (2001:db8::/32)";
        return null;
    }

    // ---- Registrable domains ---------------------------------------------------------------------------------------

    private static readonly Lazy<(HashSet<string> Rules, HashSet<string> Wild, HashSet<string> Except)> Suffixes = new(ReadSuffixes);

    private static (HashSet<string>, HashSet<string>, HashSet<string>) ReadSuffixes()
    {
        var rules = new HashSet<string>(StringComparer.Ordinal);
        var wild = new HashSet<string>(StringComparer.Ordinal);
        var except = new HashSet<string>(StringComparer.Ordinal);
        using var stream = typeof(Names).Assembly.GetManifestResourceStream("public-suffixes.txt.gz")!;
        using var reader = new StreamReader(new GZipStream(stream, CompressionMode.Decompress));
        while (reader.ReadLine() is { } line)
        {
            line = line.Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith("*.", StringComparison.Ordinal)) wild.Add(Ascii(line[2..]));
            else if (line[0] == '!') except.Add(Ascii(line[1..]));
            else rules.Add(Ascii(line));
        }
        return (rules, wild, except);
    }

    private static string Ascii(string name)
    {
        try { return Idn.GetAscii(name).ToLowerInvariant(); }
        catch (ArgumentException) { return name.ToLowerInvariant(); }
    }

    /// <summary>The part of a name its owner registered: <c>example.co.uk</c> for <c>www.example.co.uk</c>. The name
    /// itself when it's a public suffix or under an unknown one's single label; null for a bare suffix.</summary>
    public static string? RegistrableDomain(string name)
    {
        var (rules, wild, except) = Suffixes.Value;
        var labels = name.Split('.');
        // The longest rule that matches decides; an exception rule beats everything.
        for (var start = 0; start < labels.Length; start++)
        {
            var candidate = string.Join('.', labels[start..]);
            if (except.Contains(candidate))
            {
                return string.Join('.', labels[Math.Max(start, 0)..]);
            }
            var parent = start + 1 < labels.Length ? string.Join('.', labels[(start + 1)..]) : null;
            if (rules.Contains(candidate) || (parent is not null && wild.Contains(parent)))
            {
                return start == 0 ? null : string.Join('.', labels[(start - 1)..]);
            }
        }
        // Not under any listed suffix: its last label is treated as one.
        return labels.Length >= 2 ? string.Join('.', labels[^2..]) : null;
    }

    // ---- Networks --------------------------------------------------------------------------------------------------

    /// <summary>Reads <c>192.0.2.0/24</c> or a bare address. The network's own first address is what's returned, so
    /// <c>192.0.2.7/24</c> comes to 192.0.2.0.</summary>
    public static bool TryParseNetwork(string text, out IPAddress network, out int prefix)
    {
        network = IPAddress.None;
        prefix = 0;
        var slash = text.IndexOf('/');
        var host = slash >= 0 ? text[..slash] : text;
        if (!IPAddress.TryParse(host, out var address)) return false;
        var bits = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        prefix = bits;
        if (slash >= 0 && (!int.TryParse(text[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out prefix) || prefix > bits)) return false;
        network = new IPAddress(MaskBytes(address.GetAddressBytes(), prefix));
        return true;
    }

    private static byte[] MaskBytes(byte[] bytes, int prefix)
    {
        var masked = (byte[])bytes.Clone();
        for (var i = 0; i < masked.Length; i++)
        {
            var keep = Math.Clamp(prefix - i * 8, 0, 8);
            masked[i] &= (byte)(0xFF << (8 - keep));
        }
        return masked;
    }

    public static bool NetworkContains(string cidr, string ip)
    {
        if (!TryParseNetwork(cidr, out var network, out var prefix) || !IPAddress.TryParse(ip, out var address)) return false;
        if (network.AddressFamily != address.AddressFamily) return false;
        return MaskBytes(address.GetAddressBytes(), prefix).AsSpan().SequenceEqual(network.GetAddressBytes());
    }

    public static double AddressCount(string cidr)
    {
        if (!TryParseNetwork(cidr, out var network, out var prefix)) return 0;
        var bits = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        return Math.Pow(2, bits - prefix);
    }

    /// <summary>The network as <c>192.0.2.0/24</c>, or the bare address when it's a single one.</summary>
    public static string FormatNetwork(IPAddress network, int prefix)
    {
        var bits = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        return prefix == bits ? Canonical(network) : $"{Canonical(network)}/{prefix}";
    }

    /// <summary>Every address of a small network; of a larger one, <paramref name="limit"/> addresses spread evenly
    /// across it. A network's first address is usually not a host, so it's left out when a sample is taken.</summary>
    public static List<string> SampleAddresses(string cidr, int limit)
    {
        var result = new List<string>();
        if (!TryParseNetwork(cidr, out var network, out var prefix) || limit <= 0) return result;
        var bits = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var hostBits = bits - prefix;
        var first = ToNumber(network);
        if (hostBits < 63 && (1L << hostBits) <= limit)
        {
            for (var i = 0L; i < 1L << hostBits; i++) result.Add(FromNumber(first + (UInt128)i, network.AddressFamily));
            return result;
        }
        var size = hostBits >= 128 ? UInt128.MaxValue : (UInt128.One << hostBits);
        var step = size / (UInt128)limit;
        if (step == 0) step = 1;
        // Start one in: the address after the network's own.
        for (var i = 0; i < limit; i++)
        {
            result.Add(FromNumber(first + 1 + step * (UInt128)i, network.AddressFamily));
        }
        return result;
    }

    /// <summary>A network's first and last address, as numbers.</summary>
    public static bool TryGetRange(string cidr, out UInt128 first, out UInt128 last, out AddressFamily family)
    {
        first = last = 0;
        family = AddressFamily.InterNetwork;
        if (!TryParseNetwork(cidr, out var network, out var prefix)) return false;
        family = network.AddressFamily;
        var hostBits = (family == AddressFamily.InterNetwork ? 32 : 128) - prefix;
        first = ToNumber(network);
        last = hostBits >= 128 ? UInt128.MaxValue : first + (UInt128.One << hostBits) - 1;
        return true;
    }

    public static string AddressAt(UInt128 number, AddressFamily family) => FromNumber(number, family);

    private static UInt128 ToNumber(IPAddress address)
    {
        UInt128 value = 0;
        foreach (var b in address.GetAddressBytes()) value = (value << 8) | b;
        return value;
    }

    private static string FromNumber(UInt128 value, AddressFamily family)
    {
        var bytes = new byte[family == AddressFamily.InterNetwork ? 4 : 16];
        for (var i = bytes.Length - 1; i >= 0; i--)
        {
            bytes[i] = (byte)(value & 0xFF);
            value >>= 8;
        }
        return new IPAddress(bytes).ToString();
    }
}
