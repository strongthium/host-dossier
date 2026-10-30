using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Strongthium.HostDossier;

/// <summary>Reading what's in a certificate, and checking one against this computer's trusted roots.</summary>
public static partial class Certificates
{
    private const string SanOid = "2.5.29.17", PoliciesOid = "2.5.29.32", CrlOid = "2.5.29.31", TimestampsOid = "1.3.6.1.4.1.11129.2.4.2", TlsFeatureOid = "1.3.6.1.5.5.7.1.24";

    public static CertificateInfo Describe(X509Certificate2 certificate)
    {
        var (keyType, bits, curve) = ReadKey(certificate);
        var names = new List<string>();
        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid?.Value != SanOid) continue;
            var san = new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);
            names.AddRange(san.EnumerateDnsNames().Select(n => n.ToLowerInvariant()));
            names.AddRange(san.EnumerateIPAddresses().Select(Names.Canonical));
        }
        var usages = new List<string>();
        var isAuthority = false;
        string? ocsp = null, caIssuers = null, crl = null;
        var timestamps = 0;
        var mustStaple = false;
        foreach (var extension in certificate.Extensions)
        {
            switch (extension)
            {
                case X509EnhancedKeyUsageExtension eku:
                    foreach (var usage in eku.EnhancedKeyUsages) usages.Add(usage.FriendlyName ?? usage.Value ?? "?");
                    break;
                case X509BasicConstraintsExtension constraints:
                    isAuthority = constraints.CertificateAuthority;
                    break;
                case X509AuthorityInformationAccessExtension access:
                    ocsp = access.EnumerateOcspUris().FirstOrDefault();
                    caIssuers = access.EnumerateCAIssuersUris().FirstOrDefault();
                    break;
            }
            switch (extension.Oid?.Value)
            {
                case TimestampsOid:
                    timestamps = CountTimestamps(extension.RawData);
                    break;
                case TlsFeatureOid:
                    mustStaple = true;
                    break;
                case CrlOid:
                    crl = UrlInBytes().Match(Encoding.Latin1.GetString(extension.RawData)).Value is { Length: > 0 } url ? url : null;
                    break;
            }
        }
        return new CertificateInfo
        {
            Subject = certificate.Subject,
            Issuer = certificate.Issuer,
            Serial = certificate.SerialNumber,
            NotBefore = new DateTimeOffset(certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero),
            NotAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero),
            KeyType = keyType,
            KeyBits = bits,
            Curve = curve,
            SignatureAlgorithm = certificate.SignatureAlgorithm.FriendlyName ?? certificate.SignatureAlgorithm.Value ?? "?",
            Sha256 = Convert.ToHexString(SHA256.HashData(certificate.RawData)).ToLowerInvariant(),
            SpkiSha256 = Convert.ToBase64String(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo())),
            Names = names.Distinct().ToList(),
            Usages = usages,
            Validation = ValidationLevel(certificate),
            TimestampCount = timestamps,
            MustStaple = mustStaple,
            IsAuthority = isAuthority,
            SelfSigned = certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData),
            OcspUrl = ocsp,
            CaIssuersUrl = caIssuers,
            CrlUrl = crl,
        };
    }

    [GeneratedRegex(@"https?://[\x21-\x7E]+")]
    private static partial Regex UrlInBytes();

    private static (string Type, int Bits, string? Curve) ReadKey(X509Certificate2 certificate)
    {
        var oid = certificate.PublicKey.Oid.Value;
        try
        {
            switch (oid)
            {
                case "1.2.840.113549.1.1.1" or "1.2.840.113549.1.1.10":
                    using (var rsa = certificate.GetRSAPublicKey()) return ("RSA", rsa?.KeySize ?? 0, null);
                case "1.2.840.10045.2.1":
                    using (var ec = certificate.GetECDsaPublicKey())
                    {
                        var curve = ec?.ExportParameters(false).Curve.Oid;
                        return ("ECDSA", ec?.KeySize ?? 0, curve?.FriendlyName ?? curve?.Value);
                    }
                case "1.3.101.112": return ("Ed25519", 256, null);
                case "1.3.101.113": return ("Ed448", 456, null);
                case "1.2.840.10040.4.1": return ("DSA", 0, null);
            }
        }
        catch (CryptographicException)
        {
            // A key this computer can't read is still reported by its type.
        }
        return (certificate.PublicKey.Oid.FriendlyName ?? oid ?? "?", 0, null);
    }

    /// <summary>The baseline requirements' policies say how much the CA checked: only the domain, the organization, or
    /// (extended validation) the organization thoroughly.</summary>
    private static string? ValidationLevel(X509Certificate2 certificate)
    {
        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid?.Value != PoliciesOid) continue;
            try
            {
                var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
                while (reader.HasData)
                {
                    var policy = reader.ReadSequence();
                    switch (policy.ReadObjectIdentifier())
                    {
                        case "2.23.140.1.1": return "Extended validation (EV)";
                        case "2.23.140.1.2.1": return "Domain validated (DV)";
                        case "2.23.140.1.2.2": return "Organization validated (OV)";
                        case "2.23.140.1.2.3": return "Individual validated (IV)";
                    }
                }
            }
            catch (AsnContentException)
            {
                return null;
            }
        }
        return null;
    }

    /// <summary>How many Signed Certificate Timestamps are embedded: the proof of being in the public logs.</summary>
    private static int CountTimestamps(byte[] raw)
    {
        try
        {
            var list = new AsnReader(raw, AsnEncodingRules.DER).ReadOctetString();
            if (list.Length < 2) return 0;
            var position = 2;
            var count = 0;
            while (position + 2 <= list.Length)
            {
                position += 2 + ((list[position] << 8) | list[position + 1]);
                count++;
            }
            return count;
        }
        catch (AsnContentException)
        {
            return 0;
        }
    }

    /// <summary>Whether a certificate is good for a name, wildcards included, the way a browser reads it: by the
    /// alternative names only.</summary>
    public static bool Matches(X509Certificate2 certificate, string host)
    {
        try
        {
            return certificate.MatchesHostname(host, allowWildcards: true, allowCommonName: false);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>Checks a certificate and the others the server sent against this computer's trusted roots.</summary>
    public static void CheckTrust(X509Certificate2 leaf, IReadOnlyList<X509Certificate2> sent, TlsReport report)
    {
        using (var offline = new X509Chain())
        {
            offline.ChainPolicy.DisableCertificateDownloads = true;
            offline.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            offline.ChainPolicy.ExtraStore.AddRange(new X509Certificate2Collection(sent.ToArray()));
            offline.Build(leaf);
            report.ChainSentComplete = !offline.ChainStatus.Any(s => s.Status.HasFlag(X509ChainStatusFlags.PartialChain));
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(6);
        chain.ChainPolicy.ExtraStore.AddRange(new X509Certificate2Collection(sent.ToArray()));
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        chain.Build(leaf);

        // Not being able to reach the CA's revocation service is not the certificate's fault.
        const X509ChainStatusFlags Ignorable = X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation;
        var problems = chain.ChainStatus.Where(s => (s.Status & ~Ignorable) != X509ChainStatusFlags.NoError).ToList();
        report.Trusted = problems.Count == 0;
        var detail = problems.Select(s => s.StatusInformation.Trim()).Where(s => s.Length > 0).Distinct().ToList();
        if (chain.ChainStatus.Any(s => (s.Status & Ignorable) != 0)) detail.Add("Revocation couldn't be checked.");
        report.TrustDetail = detail.Count > 0 ? string.Join(" ", detail) : "Trusted by this computer's roots; not revoked.";

        report.Chain.Clear();
        foreach (var element in chain.ChainElements) report.Chain.Add(Describe(element.Certificate));
    }

    /// <summary>The names on a certificate worth looking up: wildcards as their parent domain, addresses left out.</summary>
    public static IEnumerable<string> FollowableNames(IEnumerable<string> names)
    {
        foreach (var name in names)
        {
            if (IPAddress.TryParse(name, out _)) continue;
            var plain = Names.NormalizeName(name.TrimStart('*', '.'));
            if (plain is not null) yield return plain;
        }
    }
}
