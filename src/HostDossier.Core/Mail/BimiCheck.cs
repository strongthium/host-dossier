using System.Formats.Asn1;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace Strongthium.HostDossier;

/// <summary>
/// BIMI: the logo a domain wants mail clients to show. Checks the record, the DMARC policy it depends on, the logo's
/// SVG Tiny PS rules and, when there's a mark certificate (VMC or CMC), the certificate: that it's a mark certificate,
/// for this domain, in date, its chain unbroken up to a root, and that the logo inside it is the logo published.
/// </summary>
public sealed partial class BimiCheck(Resolver resolver, HttpClient http)
{
    private const string BimiUsage = "1.3.6.1.5.5.7.3.31";
    private const string MarkTypeOid = "1.3.6.1.4.1.53087.1.13";
    private const string LogotypeOid = "1.3.6.1.5.5.7.1.12";
    private const int MaxLogo = 512 * 1024;

    /// <summary>Who issues mark certificates. Their roots aren't in Windows' store, so a chain ends at a root that's
    /// recognized here by name.</summary>
    private static readonly string[] KnownIssuers = ["DigiCert", "Entrust", "GlobalSign", "SSL.com", "Sectigo"];

    public async Task<BimiReport> CheckAsync(string domain, DmarcReport? dmarc, CancellationToken cancel)
    {
        var report = new BimiReport { Domain = domain };
        var organization = Names.RegistrableDomain(domain);
        foreach (var candidate in new[] { domain, organization }.OfType<string>().Distinct())
        {
            var name = $"default._bimi.{candidate}";
            var texts = await resolver.TextAsync(name, cancel).ConfigureAwait(false);
            var record = texts.Find(t => t.StartsWith("v=BIMI1", StringComparison.OrdinalIgnoreCase));
            if (record is null) continue;
            report.RecordAt = name;
            report.Record = record;
            break;
        }
        if (report.Record is null) return report;

        void Say(Level level, string text) => report.Findings.Add(new Finding(level, "BIMI", text));
        var tags = TagList.Parse(report.Record);
        report.LogoUrl = NonEmpty(tags.GetValueOrDefault("l"));
        report.EvidenceUrl = NonEmpty(tags.GetValueOrDefault("a"));

        if (dmarc?.Enforcing != true)
        {
            Say(Level.Bad, "BIMI needs DMARC to enforce: p=quarantine or p=reject at 100%. Without that, mail clients won't show the logo.");
        }
        if (report.LogoUrl is null && report.EvidenceUrl is null)
        {
            Say(Level.Info, "The record declines BIMI: it names no logo.");
            return report;
        }

        byte[]? logo = null;
        if (report.LogoUrl is { } logoUrl)
        {
            logo = await FetchAsync(logoUrl, report, "logo", cancel).ConfigureAwait(false);
            if (logo is not null) CheckLogo(logo, report);
        }
        else
        {
            Say(Level.Warning, "The record names no logo (l=).");
        }

        if (report.EvidenceUrl is { } evidenceUrl)
        {
            var pem = await FetchAsync(evidenceUrl, report, "certificate", cancel).ConfigureAwait(false);
            if (pem is not null) CheckCertificate(pem, logo, domain, report);
        }
        else
        {
            report.CertificateKind = "None";
            Say(Level.Notice, "There's no mark certificate (a=): Gmail and Apple Mail show a logo only with one.");
        }
        return report;
    }

    private static string? NonEmpty(string? text) => string.IsNullOrWhiteSpace(text) ? null : text.Trim();

    private async Task<byte[]?> FetchAsync(string url, BimiReport report, string what, CancellationToken cancel)
    {
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            report.Findings.Add(new Finding(Level.Bad, "BIMI", $"The {what} isn't on an https address: {url}"));
            return null;
        }
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                report.Findings.Add(new Finding(Level.Bad, "BIMI", $"The {what} answers {(int)response.StatusCode}: {url}"));
                return null;
            }
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
            var buffer = new byte[MaxLogo];
            var read = await stream.ReadAtLeastAsync(buffer, MaxLogo, throwOnEndOfStream: false, timeout.Token).ConfigureAwait(false);
            return buffer[..read];
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or OperationCanceledException && !cancel.IsCancellationRequested)
        {
            report.Findings.Add(new Finding(Level.Bad, "BIMI", $"The {what} couldn't be fetched from {url}: {exception.GetBaseException().Message}"));
            return null;
        }
    }

    /// <summary>The SVG Tiny Portable/Secure profile, as far as a reading of the file can tell.</summary>
    internal static void CheckLogo(byte[] bytes, BimiReport report)
    {
        report.LogoBytes = bytes.Length;
        report.LogoSha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var problems = new List<string>();
        if (bytes.Length > 32 * 1024) problems.Add($"it's {bytes.Length / 1024} KB, and the limit is 32 KB");
        try
        {
            using var reader = XmlReader.Create(new MemoryStream(bytes), new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, MaxCharactersFromEntities = 1024 });
            var depth0 = true;
            var title = false;
            while (reader.Read())
            {
                if (reader.NodeType != XmlNodeType.Element) continue;
                var local = reader.LocalName.ToLowerInvariant();
                if (depth0)
                {
                    depth0 = false;
                    if (local != "svg")
                    {
                        problems.Add("it isn't an SVG");
                        break;
                    }
                    if (reader.GetAttribute("baseProfile") != "tiny-ps") problems.Add("baseProfile isn't \"tiny-ps\"");
                    if (reader.GetAttribute("version") != "1.2") problems.Add("version isn't \"1.2\"");
                    if (reader.GetAttribute("x") is not null || reader.GetAttribute("y") is not null) problems.Add("the root has x or y attributes");
                    if (reader.GetAttribute("viewBox") is { } box)
                    {
                        var parts = box.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length == 4 && double.TryParse(parts[2], System.Globalization.CultureInfo.InvariantCulture, out var w) && double.TryParse(parts[3], System.Globalization.CultureInfo.InvariantCulture, out var h) && Math.Abs(w - h) > 0.5)
                        {
                            problems.Add($"it isn't square ({w:0} by {h:0})");
                        }
                    }
                    continue;
                }
                if (local == "title") title = true;
                if (local is "script" or "image" or "foreignobject" or "animate" or "animatetransform" or "animatemotion" or "set") problems.Add($"it has a <{reader.LocalName}> element, which the profile forbids");
                if (reader.GetAttribute("href", "http://www.w3.org/1999/xlink") is { } link && !link.StartsWith('#')) problems.Add("it links to something outside itself");
            }
            if (!title && !depth0) problems.Add("it has no <title>");
        }
        catch (XmlException exception)
        {
            problems.Add("it isn't valid XML: " + exception.Message);
        }
        report.LogoValid = problems.Count == 0;
        if (problems.Count == 0) report.Findings.Add(new Finding(Level.Good, "BIMI", $"The logo fits the SVG Tiny PS profile ({bytes.Length:N0} bytes)."));
        else report.Findings.Add(new Finding(Level.Warning, "BIMI", "The logo doesn't fit the SVG Tiny PS profile: " + string.Join("; ", problems.Distinct()) + "."));
    }

    internal static void CheckCertificate(byte[] pem, byte[]? logo, string domain, BimiReport report)
    {
        void Say(Level level, string text) => report.Findings.Add(new Finding(level, "BIMI", text));
        var certificates = new X509Certificate2Collection();
        try
        {
            certificates.ImportFromPem(Encoding.ASCII.GetString(pem));
        }
        catch (CryptographicException exception)
        {
            report.CertificateValid = false;
            Say(Level.Bad, "The certificate file can't be read: " + exception.Message);
            return;
        }
        if (certificates.Count == 0)
        {
            report.CertificateValid = false;
            Say(Level.Bad, "The certificate file holds no certificates.");
            return;
        }

        // The mark certificate is the one for BIMI that isn't an authority.
        var leaf = certificates.FirstOrDefault(c => HasUsage(c, BimiUsage) && !IsAuthority(c)) ?? certificates[0];
        var problems = new List<string>();
        if (!HasUsage(leaf, BimiUsage)) problems.Add("it isn't marked for BIMI (extended key usage 1.3.6.1.5.5.7.3.31)");

        report.MarkType = MarkType(leaf);
        report.CertificateKind = report.MarkType switch
        {
            null => "Mark certificate",
            "Prior Use Mark" or "Modified Registered Mark" => "Common Mark Certificate (CMC)",
            _ => "Verified Mark Certificate (VMC)",
        };

        var now = DateTime.Now;
        if (now < leaf.NotBefore) problems.Add($"it isn't valid until {leaf.NotBefore:yyyy-MM-dd}");
        if (now > leaf.NotAfter) problems.Add($"it expired on {leaf.NotAfter:yyyy-MM-dd}");

        var described = Certificates.Describe(leaf);
        var organization = Names.RegistrableDomain(domain);
        var acceptable = new[] { domain, organization, $"default._bimi.{domain}", $"default._bimi.{organization}" };
        if (!described.Names.Any(n => acceptable.Contains(n, StringComparer.OrdinalIgnoreCase)))
        {
            problems.Add($"it isn't for {domain}: it names {string.Join(", ", described.Names.Take(5))}");
        }
        if (described.TimestampCount == 0) problems.Add("it has no proof of being in the public logs (no timestamps)");

        CheckChain(leaf, certificates, report, problems);

        if (logo is not null)
        {
            var inside = LogoInCertificate(leaf);
            if (inside is null)
            {
                report.LogoMatchesCertificate = null;
                Say(Level.Notice, "The certificate holds no logo that could be read to compare with the published one.");
            }
            else
            {
                report.LogoMatchesCertificate = Normalize(inside) == Normalize(logo);
                if (report.LogoMatchesCertificate == true) Say(Level.Good, "The logo inside the certificate is the logo published.");
                else Say(Level.Bad, "The logo inside the certificate isn't the one published at l=.");
            }
        }

        report.Chain.Add(described);
        foreach (var other in certificates)
        {
            if (!other.RawData.AsSpan().SequenceEqual(leaf.RawData)) report.Chain.Add(Certificates.Describe(other));
        }
        report.CertificateValid = problems.Count == 0;
        if (problems.Count == 0) Say(Level.Good, $"The {report.CertificateKind}{(report.MarkType is null ? "" : $" ({report.MarkType})")} is valid: for this domain, in date, until {leaf.NotAfter:yyyy-MM-dd}. {report.ChainDetail}");
        else Say(Level.Bad, "The mark certificate has problems: " + string.Join("; ", problems) + ".");
    }

    private static void CheckChain(X509Certificate2 leaf, X509Certificate2Collection certificates, BimiReport report, List<string> problems)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ExtraStore.AddRange(certificates);
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(6);
        chain.Build(leaf);
        var root = chain.ChainElements[^1].Certificate;
        var flags = chain.ChainStatus.Aggregate(X509ChainStatusFlags.NoError, (all, s) => all | s.Status);
        var broken = flags & ~(X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain | X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation);
        var reachedRoot = !flags.HasFlag(X509ChainStatusFlags.PartialChain);
        var rootName = root.GetNameInfo(X509NameType.SimpleName, false);
        if (broken != X509ChainStatusFlags.NoError)
        {
            problems.Add("its chain is broken: " + string.Join(" ", chain.ChainStatus.Where(s => (s.Status & broken) != 0).Select(s => s.StatusInformation.Trim())));
            report.ChainDetail = "The chain is broken.";
        }
        else if (!reachedRoot)
        {
            problems.Add($"its chain stops at \"{rootName}\" and doesn't reach a root");
            report.ChainDetail = $"The chain stops at {rootName}.";
        }
        else if (KnownIssuers.Any(i => rootName.Contains(i, StringComparison.OrdinalIgnoreCase)))
        {
            report.ChainDetail = $"Its chain is intact up to {rootName}, a known issuer of mark certificates.";
        }
        else
        {
            problems.Add($"its root, \"{rootName}\", isn't a known issuer of mark certificates");
            report.ChainDetail = $"The chain ends at {rootName}, which isn't a known issuer.";
        }
    }

    private static bool HasUsage(X509Certificate2 certificate, string oid) =>
        certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(e => e.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>().Any(u => u.Value == oid));

    private static bool IsAuthority(X509Certificate2 certificate) =>
        certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority);

    private static string? MarkType(X509Certificate2 certificate)
    {
        foreach (var part in certificate.SubjectName.EnumerateRelativeDistinguishedNames())
        {
            if (part.HasMultipleElements) continue;
            if (part.GetSingleElementType().Value == MarkTypeOid) return part.GetSingleElementValue();
        }
        return null;
    }

    /// <summary>The logo a mark certificate carries in its logotype extension: a data address, usually gzipped.</summary>
    internal static byte[]? LogoInCertificate(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.FirstOrDefault(e => e.Oid?.Value == LogotypeOid);
        if (extension is null) return null;
        var text = Encoding.Latin1.GetString(extension.RawData);
        var match = DataAddress().Match(text);
        if (!match.Success) return null;
        byte[] data;
        try
        {
            data = Convert.FromBase64String(match.Groups[1].Value);
        }
        catch (FormatException)
        {
            return null;
        }
        if (data.Length > 2 && data[0] == 0x1F && data[1] == 0x8B)
        {
            try
            {
                using var gunzip = new GZipStream(new MemoryStream(data), CompressionMode.Decompress);
                using var output = new MemoryStream();
                gunzip.CopyTo(output);
                return output.ToArray();
            }
            catch (InvalidDataException)
            {
                return null;
            }
        }
        return data;
    }

    private static string Normalize(byte[] svg) => WhiteSpace().Replace(Encoding.UTF8.GetString(svg), "");

    [GeneratedRegex(@"data:image/svg\+xml[^,]*;base64,([A-Za-z0-9+/=]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DataAddress();

    [GeneratedRegex(@"\s+")]
    private static partial Regex WhiteSpace();
}
