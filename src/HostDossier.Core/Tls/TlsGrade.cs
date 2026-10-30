namespace Strongthium.HostDossier;

/// <summary>
/// A letter for a TLS server, by rules modelled on SSL Labs' published guide. It's this program's own judgement, not
/// their rating: each thing that holds the grade down is listed beside it, so the letter can always be checked.
/// </summary>
public static class TlsGrade
{
    private static readonly string[] Order = ["A+", "A", "A-", "B", "C", "D", "E", "F", "T"];

    public static void Apply(TlsReport report)
    {
        var grade = "A";
        void Cap(string limit, string reason)
        {
            report.GradeReasons.Add($"{limit}: {reason}");
            if (Array.IndexOf(Order, limit) > Array.IndexOf(Order, grade)) grade = limit;
        }
        void Say(Level level, string text) => report.Findings.Add(new Finding(level, "TLS", text));

        var supported = report.Protocols.Where(p => p.Supported).ToList();
        var ciphers = supported.SelectMany(p => p.Ciphers).DistinctBy(c => c.Id).ToList();

        // Protocols
        if (report.Protocols.Find(p => p.Name == "SSL 2.0")?.Supported == true)
        {
            Cap("F", "SSL 2.0 is supported");
            Say(Level.Bad, "SSL 2.0 is supported. It has been broken for decades and allows the DROWN attack.");
        }
        if (report.Protocols.Find(p => p.Name == "SSL 3.0")?.Supported == true)
        {
            Cap("C", "SSL 3.0 is supported");
            Say(Level.Bad, "SSL 3.0 is supported, which is open to POODLE.");
        }
        var oldTls = supported.Where(p => p.Name is "TLS 1.0" or "TLS 1.1").Select(p => p.Name).ToList();
        if (oldTls.Count > 0)
        {
            Cap("B", $"{string.Join(" and ", oldTls)} supported");
            Say(Level.Warning, $"{string.Join(" and ", oldTls)} supported. Both were retired in 2021 (RFC 8996).");
        }
        var tls13 = report.Protocols.Find(p => p.Name == "TLS 1.3")?.Supported == true;
        if (tls13) Say(Level.Good, "TLS 1.3 is supported.");
        else
        {
            Cap("A-", "no TLS 1.3");
            Say(Level.Notice, "TLS 1.3 isn't supported.");
        }

        // Ciphers
        if (ciphers.Exists(c => c.Encryption == "None" || c.Authentication == "None"))
        {
            Cap("F", "a cipher without encryption or without authentication");
            Say(Level.Bad, "A cipher with no encryption or no authentication is accepted.");
        }
        if (ciphers.Exists(c => c.KeyExchange.Contains("export")))
        {
            Cap("F", "an export cipher");
            Say(Level.Bad, "An export cipher is accepted, which allows FREAK or Logjam.");
        }
        if (ciphers.Exists(c => c.Encryption.StartsWith("RC4", StringComparison.Ordinal)))
        {
            Cap("C", "RC4");
            Say(Level.Bad, "RC4 is accepted, which is broken.");
        }
        if (ciphers.Exists(c => c.Encryption.StartsWith("DES", StringComparison.Ordinal)))
        {
            Cap("F", "single DES");
            Say(Level.Bad, "Single DES is accepted.");
        }
        if (ciphers.Exists(c => c.Encryption.StartsWith("3DES", StringComparison.Ordinal)))
        {
            Cap("C", "3DES");
            Say(Level.Warning, "3DES is accepted, which is open to SWEET32.");
        }
        if (ciphers.Count > 0 && !ciphers.Exists(c => c.ForwardSecret))
        {
            Cap("B", "no forward secrecy");
            Say(Level.Warning, "No cipher with forward secrecy: recorded traffic can be read later by anyone who gets the key.");
        }
        else if (ciphers.Count > 0 && ciphers.Exists(c => !c.ForwardSecret))
        {
            Say(Level.Notice, "Some ciphers without forward secrecy are accepted.");
        }
        if (ciphers.Count > 0 && !ciphers.Exists(c => c.Aead))
        {
            Cap("B", "no authenticated (AEAD) cipher");
            Say(Level.Warning, "No authenticated (AEAD) cipher: only CBC, or worse.");
        }
        if (supported.Exists(p => p.Name == "TLS 1.0") && ciphers.Exists(c => c.Encryption.Contains("CBC") && c.Bits > 0) && report.ServerChoosesCipher == false)
        {
            Say(Level.Notice, "CBC under TLS 1.0 with the client's choice of cipher: open to BEAST in old browsers.");
        }

        // Key exchange
        if (report.DhBits is { } dhText && int.TryParse(dhText, out var dh))
        {
            if (dh < 1024)
            {
                Cap("F", $"{dh}-bit Diffie-Hellman");
                Say(Level.Bad, $"{dh}-bit Diffie-Hellman, which allows Logjam.");
            }
            else if (dh < 2048)
            {
                Cap("B", $"{dh}-bit Diffie-Hellman");
                Say(Level.Warning, $"{dh}-bit Diffie-Hellman is weaker than the rest of the connection.");
            }
        }
        if (report.Groups.Exists(g => g.Contains("post-quantum"))) Say(Level.Good, "A post-quantum key exchange is available.");

        // Features
        if (report.Compression == true)
        {
            Cap("C", "TLS compression");
            Say(Level.Bad, "TLS compression is on, which allows CRIME.");
        }
        if (report.SecureRenegotiation == false && supported.Exists(p => p.Name != "TLS 1.3"))
        {
            Cap("C", "no secure renegotiation");
            Say(Level.Warning, "No secure renegotiation (RFC 5746).");
        }
        if (report.FallbackProtected == false) Say(Level.Notice, "A downgrade isn't refused: TLS_FALLBACK_SCSV isn't honoured.");
        if (report.HeartbeatOffered == true) Say(Level.Info, "The heartbeat extension is on. Whether it's open to Heartbleed wasn't tested, since testing means trying the attack.");

        // The certificate
        if (report.Chain.Count > 0)
        {
            var leaf = report.Chain[0];
            var now = DateTimeOffset.UtcNow;
            if (now > leaf.NotAfter)
            {
                Cap("T", "the certificate has expired");
                Say(Level.Bad, $"The certificate expired on {leaf.NotAfter:yyyy-MM-dd}.");
            }
            else if (now < leaf.NotBefore)
            {
                Cap("T", "the certificate isn't valid yet");
                Say(Level.Bad, $"The certificate isn't valid until {leaf.NotBefore:yyyy-MM-dd}.");
            }
            else if ((leaf.NotAfter - now).TotalDays < 14)
            {
                Say(Level.Warning, $"The certificate expires in {(int)(leaf.NotAfter - now).TotalDays} days.");
            }
            if (report.Trusted == false)
            {
                Cap("T", "the certificate isn't trusted");
                Say(Level.Bad, "The certificate isn't trusted: " + report.TrustDetail);
            }
            if (report.NameMatches == false)
            {
                Cap("T", $"the certificate isn't for {report.Host}");
                Say(Level.Bad, $"The certificate isn't for {report.Host}.");
            }
            if (report.ChainSentComplete == false && report.Trusted == true) Say(Level.Warning, "The server doesn't send the whole chain: clients that can't fetch the missing certificate will fail.");
            if (leaf.KeyType == "RSA" && leaf.KeyBits is > 0 and < 2048)
            {
                Cap("F", $"a {leaf.KeyBits}-bit RSA key");
                Say(Level.Bad, $"The certificate has a {leaf.KeyBits}-bit RSA key.");
            }
            if (leaf.KeyType == "ECDSA" && leaf.KeyBits is > 0 and < 256) Cap("B", $"a {leaf.KeyBits}-bit ECDSA key");
            if (leaf.SignatureAlgorithm.Contains("sha1", StringComparison.OrdinalIgnoreCase) || leaf.SignatureAlgorithm.Contains("md5", StringComparison.OrdinalIgnoreCase))
            {
                Cap("T", "a certificate signed with " + leaf.SignatureAlgorithm);
                Say(Level.Bad, $"The certificate is signed with {leaf.SignatureAlgorithm}.");
            }
            if (leaf.MustStaple && report.OcspStapled == false) Say(Level.Bad, "The certificate says it must be stapled, and the server doesn't staple it.");
        }

        report.Grade = grade;
    }

    /// <summary>A strong HTTP Strict Transport Security header is what lifts an A to an A+.</summary>
    public static void ApplyHsts(TlsReport report, long? maxAge)
    {
        if (maxAge is >= 15_552_000 && report.Grade == "A")
        {
            report.Grade = "A+";
            report.GradeReasons.Add("A+: HSTS for at least six months");
        }
    }
}
