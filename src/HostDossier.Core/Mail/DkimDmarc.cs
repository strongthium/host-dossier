using System.Security.Cryptography;
using DnsClient;

namespace Strongthium.HostDossier;

/// <summary>
/// DKIM keys. The DNS has no way to list them, so a domain's selectors can't be enumerated, only guessed: common ones
/// are tried, and the settings can add others. A signed message's headers would name the real one.
/// </summary>
public sealed class DkimCheck(Resolver resolver)
{
    public static readonly string[] DefaultSelectors =
    [
        "default", "dkim", "mail", "email", "smtp", "key1", "key2", "k1", "k2", "k3", "s1", "s2", "s1024", "s2048", "sm1", "sm2", "sig1",
        "google", "selector1", "selector2", "selector", "mandrill", "mailgun", "mg", "smtpapi", "sendgrid", "pm", "postmark", "fm1", "fm2", "fm3",
        "protonmail", "protonmail2", "protonmail3", "zoho", "zmail", "amazonses", "ses", "hs1", "hs2", "zendesk1", "zendesk2", "mxvault", "everlytickey1", "everlytickey2", "dkim1", "dkim2", "mimecast", "mimecast20190104", "turbo-smtp", "cm", "krs", "mte1", "mte2", "cf2024-1", "20230601", "20221208", "20210112", "20161025",
    ];

    public async Task<DkimReport> CheckAsync(string domain, IReadOnlyList<string> selectors, CancellationToken cancel)
    {
        var report = new DkimReport { Domain = domain, SelectorsTried = selectors.Count };
        var node = await resolver.QueryAsync($"_domainkey.{domain}", QueryType.TXT, cancel).ConfigureAwait(false);
        report.DomainKeyNode = node.Outcome switch
        {
            DnsOutcome.NoSuchName => "none",
            DnsOutcome.NoData or DnsOutcome.Answered => "some",
            _ => null,
        };
        var found = await Task.WhenAll(selectors.Select(async selector =>
        {
            var name = $"{selector}._domainkey.{domain}";
            var texts = await resolver.TextAsync(name, cancel).ConfigureAwait(false);
            return texts.Where(IsKey).Select(text => ReadKey(selector, name, text)).ToList();
        })).ConfigureAwait(false);
        report.Keys.AddRange(found.SelectMany(k => k));
        Judge(report);
        return report;
    }

    /// <summary>A DKIM record has a p= tag; a domain's wildcard TXT or something else at the name doesn't.</summary>
    private static bool IsKey(string text) => TagList.Parse(text).ContainsKey("p");

    internal static DkimKey ReadKey(string selector, string name, string text)
    {
        var tags = TagList.Parse(text);
        var key = new DkimKey { Selector = selector, Name = name, Record = text, Service = KnownServices.ForDkimSelector(selector) };
        if (tags.TryGetValue("k", out var type)) key.KeyType = type.ToLowerInvariant();
        if (tags.TryGetValue("t", out var flags)) key.Testing = flags.Split(':').Contains("y");
        if (tags.TryGetValue("h", out var hashes)) key.Hashes = hashes;
        var data = tags.GetValueOrDefault("p", "").Replace(" ", "");
        if (data.Length == 0)
        {
            key.Revoked = true;
            return key;
        }
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(data);
        }
        catch (FormatException)
        {
            key.Problem = "The key isn't valid base64.";
            return key;
        }
        if (key.KeyType == "ed25519")
        {
            key.Bits = 256;
            if (bytes.Length != 32) key.Problem = $"An Ed25519 key is 32 bytes, and this is {bytes.Length}.";
            return key;
        }
        try
        {
            using var rsa = RSA.Create();
            try { rsa.ImportSubjectPublicKeyInfo(bytes, out _); }
            catch (CryptographicException) { rsa.ImportRSAPublicKey(bytes, out _); }
            key.Bits = rsa.KeySize;
        }
        catch (CryptographicException)
        {
            key.Problem = "The key can't be read as an RSA key.";
        }
        return key;
    }

    private static void Judge(DkimReport report)
    {
        void Say(Level level, string text) => report.Findings.Add(new Finding(level, "DKIM", text));
        if (report.Keys.Count == 0)
        {
            Say(Level.Notice, report.DomainKeyNode == "none"
                ? $"No DKIM keys found, and nothing exists under _domainkey.{report.Domain}, which suggests there are none."
                : $"No DKIM key at the {report.SelectorsTried} common selectors tried. The domain may still use one under another name: a signed message's headers would show it.");
            return;
        }
        foreach (var key in report.Keys)
        {
            if (key.Problem is { } problem) Say(Level.Bad, $"Selector {key.Selector}: {problem}");
            else if (key.Revoked) Say(Level.Info, $"Selector {key.Selector} is revoked: its key is empty.");
            else if (key.KeyType == "rsa" && key.Bits < 1024) Say(Level.Bad, $"Selector {key.Selector} has a {key.Bits}-bit RSA key. RFC 8301 says verifiers must refuse under 1024.");
            else if (key.KeyType == "rsa" && key.Bits < 2048) Say(Level.Notice, $"Selector {key.Selector} has a {key.Bits}-bit RSA key; 2048 is the recommendation.");
            else Say(Level.Good, $"Selector {key.Selector} has a {key.Bits}-bit {(key.KeyType == "rsa" ? "RSA" : key.KeyType)} key.");
            if (key.Testing) Say(Level.Notice, $"Selector {key.Selector} says it's in testing (t=y): receivers may ignore failures.");
        }
    }
}

/// <summary>DMARC, RFC 7489: the policy at <c>_dmarc</c>, on the domain or else its registrable parent, and whether
/// reports may go where it asks them to.</summary>
public sealed class DmarcCheck(Resolver resolver)
{
    public async Task<DmarcReport> CheckAsync(string domain, CancellationToken cancel)
    {
        var report = new DmarcReport { Domain = domain };
        var organization = Names.RegistrableDomain(domain);
        foreach (var candidate in new[] { domain, organization }.OfType<string>().Distinct())
        {
            var texts = await resolver.TextAsync($"_dmarc.{candidate}", cancel).ConfigureAwait(false);
            var records = texts.Where(t => t.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)).ToList();
            if (records.Count == 0) continue;
            report.RecordAt = $"_dmarc.{candidate}";
            report.Record = records[0];
            if (records.Count > 1) report.Findings.Add(new Finding(Level.Bad, "DMARC", $"_dmarc.{candidate} has {records.Count} DMARC records. With more than one, receivers ignore them all."));
            break;
        }
        if (report.Record is null)
        {
            report.Findings.Add(new Finding(Level.Warning, "DMARC", $"{domain} has no DMARC record: nothing tells receivers what to do with forged mail."));
            return report;
        }
        Read(report);
        await VerifyReportTargetsAsync(report, organization ?? domain, cancel).ConfigureAwait(false);
        Judge(report);
        return report;
    }

    private static void Read(DmarcReport report)
    {
        var tags = TagList.Parse(report.Record!);
        report.Policy = tags.GetValueOrDefault("p")?.ToLowerInvariant();
        report.SubdomainPolicy = tags.GetValueOrDefault("sp")?.ToLowerInvariant();
        if (tags.TryGetValue("pct", out var percent) && int.TryParse(percent, out var value)) report.Percent = value;
        if (tags.TryGetValue("adkim", out var dkim)) report.AlignDkim = dkim.ToLowerInvariant();
        if (tags.TryGetValue("aspf", out var spf)) report.AlignSpf = spf.ToLowerInvariant();
        report.AggregateTo.AddRange(Addresses(tags.GetValueOrDefault("rua")));
        report.FailureTo.AddRange(Addresses(tags.GetValueOrDefault("ruf")));
    }

    private static IEnumerable<string> Addresses(string? list) =>
        (list ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(a => a.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) ? a[7..] : a);

    /// <summary>A domain may only send its reports to another domain if that domain agrees, with a record of its own.</summary>
    private async Task VerifyReportTargetsAsync(DmarcReport report, string organization, CancellationToken cancel)
    {
        foreach (var target in report.AggregateTo.Concat(report.FailureTo).Distinct())
        {
            var at = target.LastIndexOf('@');
            if (at < 0) continue;
            var host = Names.NormalizeName(target[(at + 1)..].Split('!')[0]);
            if (host is null) continue;
            var owner = Names.RegistrableDomain(host);
            if (owner == organization) continue;
            var texts = await resolver.TextAsync($"{organization}._report._dmarc.{host}", cancel).ConfigureAwait(false);
            if (!texts.Exists(t => t.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)))
            {
                report.Findings.Add(new Finding(Level.Notice, "DMARC", $"Reports go to {target}, but {host} hasn't published the record agreeing to receive them, so they may not be sent."));
            }
        }
    }

    private static void Judge(DmarcReport report)
    {
        void Say(Level level, string text) => report.Findings.Add(new Finding(level, "DMARC", text));
        switch (report.Policy)
        {
            case "reject": Say(Level.Good, "The policy is reject: forged mail is refused."); break;
            case "quarantine": Say(Level.Good, "The policy is quarantine: forged mail goes to spam."); break;
            case "none": Say(Level.Notice, "The policy is none: forged mail is only reported, and still delivered."); break;
            default: Say(Level.Bad, $"The policy is \"{report.Policy ?? "missing"}\": without a valid p= tag the record is invalid."); break;
        }
        if (report.Percent < 100) Say(Level.Notice, $"It applies to only {report.Percent}% of mail.");
        if (report.Policy is "reject" or "quarantine" && report.SubdomainPolicy == "none") Say(Level.Warning, "Subdomains are left out (sp=none): forged mail from a made-up subdomain is still delivered.");
        if (report.AggregateTo.Count == 0) Say(Level.Notice, "No address for reports (rua): nobody hears how the domain's mail is doing.");
    }
}

/// <summary>The <c>tag=value; tag=value</c> form that DKIM, DMARC, BIMI, MTA-STS and TLS-RPT records all share.</summary>
internal static class TagList
{
    public static Dictionary<string, string> Parse(string text)
    {
        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in text.Split(';'))
        {
            var equals = part.IndexOf('=');
            if (equals <= 0) continue;
            tags.TryAdd(part[..equals].Trim(), part[(equals + 1)..].Trim());
        }
        return tags;
    }
}
