namespace Strongthium.HostDossier;

/// <summary>What each cipher suite in IANA's registry is made of, read from its name, and how far to trust it.</summary>
internal static partial class CipherSuites
{
    public const string Insecure = "Insecure";
    public const string Weak = "Weak";
    public const string Acceptable = "Acceptable";
    public const string Strong = "Strong";

    private static readonly Dictionary<ushort, CipherResult> ById = Registry
        .Where(r => r.Name is not ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV" or "TLS_FALLBACK_SCSV"))
        .ToDictionary(r => r.Id, r => Describe(r.Id, r.Name));

    /// <summary>Suites a server could choose without a pre-shared key or Kerberos, strongest first, so that a server
    /// that takes the first it knows shows its best.</summary>
    private static readonly ushort[] Offerable = ById.Values
        .Where(c => !IsTls13(c.Id) && !c.KeyExchange.Contains("PSK") && !c.KeyExchange.Contains("SRP") && !c.KeyExchange.Contains("KRB5") && !c.Name.Contains("_ECCPWD_"))
        .OrderBy(c => c.Strength switch { Strong => 0, Acceptable => 1, Weak => 2, _ => 3 })
        .ThenByDescending(c => c.Bits)
        .Select(c => c.Id)
        .ToArray();

    public static readonly ushort[] Tls13 = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305];

    /// <summary>What's offered for TLS 1.2: everything.</summary>
    public static IReadOnlyList<ushort> ForTls12 => Offerable;

    /// <summary>What's offered before TLS 1.2, which knows no AEAD and no SHA-2 MACs.</summary>
    public static IReadOnlyList<ushort> ForOlder { get; } = Offerable.Where(id => !ById[id].Aead && !ById[id].Name.EndsWith("256", StringComparison.Ordinal) && !ById[id].Name.EndsWith("384", StringComparison.Ordinal)).ToArray();

    /// <summary>The usual ones, for servers that choke on a long list.</summary>
    public static readonly ushort[] Common =
    [
        0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC02B, 0xC02F, 0xC024, 0xC028, 0xC023, 0xC027, 0xC00A, 0xC014, 0xC009, 0xC013,
        0x009F, 0x009E, 0x0039, 0x0033, 0x009D, 0x009C, 0x003D, 0x003C, 0x0035, 0x002F, 0x000A,
    ];

    public static bool IsTls13(ushort id) => id is >= 0x1301 and <= 0x1305;

    public static CipherResult Find(ushort id) =>
        ById.TryGetValue(id, out var cipher) ? cipher : new CipherResult(id, $"Unknown (0x{id:X4})", "?", "?", "?", 0, Weak, false, false);

    /// <summary>Suites a server shouldn't accept today: tried on their own in a quick test.</summary>
    public static IReadOnlyList<ushort> Bad(bool tls12) =>
        (tls12 ? Offerable : ForOlder).Where(id => ById[id].Strength == Insecure || ById[id].Encryption.StartsWith("3DES", StringComparison.Ordinal)).ToArray();

    internal static CipherResult Describe(ushort id, string name)
    {
        var body = name.StartsWith("TLS_", StringComparison.Ordinal) ? name[4..] : name;
        var with = body.IndexOf("_WITH_", StringComparison.Ordinal);
        string exchange, authentication, encryptionText;
        if (with < 0)
        {
            // TLS 1.3 names only the encryption: the key exchange is always ephemeral.
            exchange = "ECDHE/DHE";
            authentication = "Certificate";
            encryptionText = body;
        }
        else
        {
            var left = body[..with];
            encryptionText = body[(with + 6)..];
            (exchange, authentication) = left switch
            {
                "RSA" => ("RSA", "RSA"),
                "RSA_EXPORT" => ("RSA (export)", "RSA"),
                _ when left.StartsWith("DH_anon", StringComparison.Ordinal) => ("DH", "None"),
                _ when left.StartsWith("ECDH_anon", StringComparison.Ordinal) => ("ECDH", "None"),
                _ when left.Contains('_') => (left[..left.IndexOf('_')], left[(left.IndexOf('_') + 1)..]),
                _ => (left, left),
            };
            if (left.Contains("EXPORT") && !exchange.Contains("export")) exchange += " (export)";
        }

        var (encryption, bits, aead) = ReadEncryption(encryptionText);
        var ephemeral = with < 0 || exchange.StartsWith("DHE", StringComparison.Ordinal) || exchange.StartsWith("ECDHE", StringComparison.Ordinal);
        var strength = Rate(name, exchange, authentication, encryption, bits, ephemeral, aead);
        return new CipherResult(id, name, exchange, authentication, encryption, bits, strength, ephemeral && authentication != "None", aead);
    }

    private static (string Name, int Bits, bool Aead) ReadEncryption(string text)
    {
        if (text.StartsWith("NULL", StringComparison.Ordinal)) return ("None", 0, false);
        if (text.StartsWith("CHACHA20_POLY1305", StringComparison.Ordinal)) return ("ChaCha20-Poly1305", 256, true);
        if (text.StartsWith("3DES_EDE_CBC", StringComparison.Ordinal)) return ("3DES CBC", 112, false);
        if (text.StartsWith("DES40_CBC", StringComparison.Ordinal)) return ("DES CBC", 40, false);
        if (text.StartsWith("DES_CBC_40", StringComparison.Ordinal)) return ("DES CBC", 40, false);
        if (text.StartsWith("DES_CBC", StringComparison.Ordinal)) return ("DES CBC", 56, false);
        if (text.StartsWith("RC4_128", StringComparison.Ordinal)) return ("RC4", 128, false);
        if (text.StartsWith("RC4_40", StringComparison.Ordinal)) return ("RC4", 40, false);
        if (text.StartsWith("RC2_CBC_40", StringComparison.Ordinal)) return ("RC2 CBC", 40, false);
        if (text.StartsWith("IDEA_CBC", StringComparison.Ordinal)) return ("IDEA CBC", 128, false);
        if (text.StartsWith("SEED_CBC", StringComparison.Ordinal)) return ("SEED CBC", 128, false);
        foreach (var family in (string[])["AES", "CAMELLIA", "ARIA", "SM4"])
        {
            if (!text.StartsWith(family, StringComparison.Ordinal)) continue;
            var parts = text.Split('_');
            var bits = parts.Length > 1 && int.TryParse(parts[1], out var size) ? size : 128;
            var display = family == "CAMELLIA" ? "Camellia" : family == "ARIA" ? "ARIA" : family;
            if (text.Contains("_GCM", StringComparison.Ordinal)) return ($"{display} GCM", bits, true);
            if (text.Contains("_CCM_8", StringComparison.Ordinal)) return ($"{display} CCM-8", bits, true);
            if (text.Contains("_CCM", StringComparison.Ordinal)) return ($"{display} CCM", bits, true);
            if (text.Contains("_CBC", StringComparison.Ordinal)) return ($"{display} CBC", bits, false);
            return (display, bits, false);
        }
        return (text, 0, false);
    }

    private static string Rate(string name, string exchange, string authentication, string encryption, int bits, bool ephemeral, bool aead)
    {
        if (encryption == "None" || authentication == "None" || exchange.Contains("export") || bits < 112) return Insecure;
        if (encryption.StartsWith("RC4", StringComparison.Ordinal) || encryption.StartsWith("RC2", StringComparison.Ordinal)) return Insecure;
        if (name.EndsWith("_MD5", StringComparison.Ordinal)) return Insecure;
        if (encryption.StartsWith("3DES", StringComparison.Ordinal)) return Weak;
        if (!ephemeral) return Weak;
        return aead ? Strong : Acceptable;
    }

    // ---- Named groups ------------------------------------------------------------------------------------------------

    public static readonly (ushort Id, string Name)[] Groups =
    [
        (0x11EC, "X25519MLKEM768 (post-quantum)"), (0x11EB, "SecP256r1MLKEM768 (post-quantum)"), (0x11ED, "SecP384r1MLKEM1024 (post-quantum)"), (0x6399, "X25519Kyber768Draft00 (post-quantum, obsolete)"),
        (0x001D, "x25519"), (0x001E, "x448"), (0x0017, "secp256r1"), (0x0018, "secp384r1"), (0x0019, "secp521r1"),
        (0x0100, "ffdhe2048"), (0x0101, "ffdhe3072"), (0x0102, "ffdhe4096"), (0x0103, "ffdhe6144"), (0x0104, "ffdhe8192"),
        (0x0016, "secp256k1"), (0x0015, "secp224r1"), (0x0014, "secp224k1"), (0x0013, "secp192r1"), (0x0012, "secp192k1"),
        (0x001A, "brainpoolP256r1"), (0x001B, "brainpoolP384r1"), (0x001C, "brainpoolP512r1"),
    ];

    public static string GroupName(ushort id) => Array.Find(Groups, g => g.Id == id) is { Name: not null } group ? group.Name : $"0x{id:X4}";
}
