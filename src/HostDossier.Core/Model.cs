namespace Strongthium.HostDossier;

/// <summary>How much a finding matters, from good news to something that's wrong.</summary>
public enum Level { Good, Info, Notice, Warning, Bad }

/// <summary>Something worth saying about what was found.</summary>
public sealed record Finding(Level Level, string Area, string Text);

public enum TargetKind { Domain, Address }

/// <summary>What was asked about: a name (always ASCII, lower case, no final dot) or an address.</summary>
public sealed record Target(string Input, TargetKind Kind, string Name, string? Registrable);

// ---- Ownership -----------------------------------------------------------------------------------------------------

public sealed record Contact(string Role, string? Name, string? Organization, string? Email, string? Phone, string? Address, string? Country);

public sealed record WhoisResponse(string Server, string Text);

/// <summary>Who registered a domain, from RDAP (the registries' structured service) and WHOIS.</summary>
public sealed class Registration
{
    public required string Domain { get; init; }
    public string? Source { get; set; }
    public string? Registrar { get; set; }
    public string? RegistrarId { get; set; }
    public string? RegistrarUrl { get; set; }
    public DateTimeOffset? Created { get; set; }
    public DateTimeOffset? Updated { get; set; }
    public DateTimeOffset? Expires { get; set; }
    public List<string> Statuses { get; } = [];
    public List<string> NameServers { get; } = [];
    public bool? DnssecSigned { get; set; }
    public List<Contact> Contacts { get; } = [];
    public string? AbuseEmail { get; set; }
    public string? AbusePhone { get; set; }
    public List<WhoisResponse> Whois { get; } = [];
    public string? Error { get; set; }
}

/// <summary>Who an address block is assigned to, from the regional registry's RDAP.</summary>
public sealed class NetworkOwner
{
    public string? Handle { get; set; }
    public string? Name { get; set; }
    public string? Range { get; set; }
    public string? Type { get; set; }
    public string? Country { get; set; }
    public string? Organization { get; set; }
    public string? AbuseEmail { get; set; }
    public DateTimeOffset? Registered { get; set; }
    public DateTimeOffset? Updated { get; set; }
    public List<Contact> Contacts { get; } = [];
    public List<WhoisResponse> Whois { get; } = [];
    public string? Error { get; set; }
}

public enum ServiceKind { Unknown, Cdn, Cloud, Hosting, Mail, Isp, Dns, Security }

/// <summary>Everything known about one address.</summary>
public sealed class AddressInfo
{
    public required string Ip { get; init; }
    /// <summary>"Private network", "Loopback" and so on when the address isn't on the public internet.</summary>
    public string? Special { get; set; }
    public long? Asn { get; set; }
    public string? AsName { get; set; }
    public string? Prefix { get; set; }
    public string? Country { get; set; }
    public string? Registry { get; set; }
    public string? Allocated { get; set; }
    /// <summary>The service the address is on, by its network: "Cloudflare", "Amazon Web Services".</summary>
    public string? Provider { get; set; }
    public ServiceKind ProviderKind { get; set; }
    public List<string> ReverseNames { get; } = [];
    /// <summary>Why there are no reverse names when it isn't that the address has none.</summary>
    public string? ReverseNote { get; set; }
    /// <summary>Whether a reverse name leads back to this address. Null when there's no reverse name.</summary>
    public bool? ForwardConfirmed { get; set; }
    public NetworkOwner? Owner { get; set; }
    /// <summary>Why this address is in the report: "A of example.com", "MX mail.example.com".</summary>
    public List<string> Roles { get; } = [];
}

// ---- DNS -----------------------------------------------------------------------------------------------------------

public sealed record DnsRow(string Name, string Type, int Ttl, string Value);

public sealed record Subdomain(string Name, string Source, IReadOnlyList<string> Addresses);

public sealed class DnsReport
{
    public List<DnsRow> Records { get; } = [];
    public List<string> Problems { get; } = [];
    public List<Subdomain> Subdomains { get; } = [];
    public string? SubdomainsNote { get; set; }
    public IReadOnlyList<string> WildcardAddresses { get; set; } = [];
    public string? DnsProvider { get; set; }
    public bool? Signed { get; set; }
    public bool? ValidatedByResolver { get; set; }
    public string? ResolverUsed { get; set; }
    public List<Finding> Findings { get; } = [];
}

// ---- TLS -----------------------------------------------------------------------------------------------------------

public sealed record CipherResult(ushort Id, string Name, string KeyExchange, string Authentication, string Encryption, int Bits, string Strength, bool ForwardSecret, bool Aead);

public sealed class ProtocolResult
{
    public required string Name { get; init; }
    public bool Supported { get; set; }
    public bool Tested { get; set; } = true;
    public List<CipherResult> Ciphers { get; } = [];
    public string? Note { get; set; }
}

public sealed class CertificateInfo
{
    public required string Subject { get; init; }
    public required string Issuer { get; init; }
    public required string Serial { get; init; }
    public DateTimeOffset NotBefore { get; init; }
    public DateTimeOffset NotAfter { get; init; }
    public required string KeyType { get; init; }
    public int KeyBits { get; init; }
    public string? Curve { get; init; }
    public required string SignatureAlgorithm { get; init; }
    public required string Sha256 { get; init; }
    public required string SpkiSha256 { get; init; }
    public IReadOnlyList<string> Names { get; init; } = [];
    public IReadOnlyList<string> Usages { get; init; } = [];
    public string? Validation { get; init; }
    public int TimestampCount { get; init; }
    public bool MustStaple { get; init; }
    public bool IsAuthority { get; init; }
    public bool SelfSigned { get; init; }
    public string? OcspUrl { get; init; }
    public string? CaIssuersUrl { get; init; }
    public string? CrlUrl { get; init; }
}

public sealed class TlsReport
{
    public required string Host { get; init; }
    public required string Ip { get; init; }
    public required int Port { get; init; }
    public string? Sni { get; init; }
    public string StartTls { get; init; } = "";
    public bool Thorough { get; set; }
    public string? Error { get; set; }
    public List<ProtocolResult> Protocols { get; } = [];
    /// <summary>True when the server chooses the cipher, false when it takes the client's first choice.</summary>
    public bool? ServerChoosesCipher { get; set; }
    public List<string> Groups { get; } = [];
    public string? DhBits { get; set; }
    public List<string> Alpn { get; } = [];
    public bool? OcspStapled { get; set; }
    public bool? SecureRenegotiation { get; set; }
    public bool? ExtendedMasterSecret { get; set; }
    public bool? SessionTickets { get; set; }
    public bool? Compression { get; set; }
    public bool? FallbackProtected { get; set; }
    public bool? HeartbeatOffered { get; set; }
    public bool? SniRequired { get; set; }
    public List<CertificateInfo> Chain { get; } = [];
    public bool? ChainSentComplete { get; set; }
    public bool? Trusted { get; set; }
    public string? TrustDetail { get; set; }
    public bool? NameMatches { get; set; }
    public string? Grade { get; set; }
    public List<string> GradeReasons { get; } = [];
    public List<Finding> Findings { get; } = [];
    /// <summary>The names on the server's certificate that are worth following.</summary>
    [System.Text.Json.Serialization.JsonIgnore] public IEnumerable<string> CertificateNames => Chain.Count > 0 ? Chain[0].Names : [];
}

// ---- Ports ---------------------------------------------------------------------------------------------------------

public sealed record OpenPort(int Port, string Service, string? Product, string? Version, string? Banner, bool Announced, bool Tls);

public sealed class PortReport
{
    public required string Ip { get; init; }
    public int Scanned { get; set; }
    public int Closed { get; set; }
    public int Filtered { get; set; }
    public List<OpenPort> Open { get; } = [];
    public string? Skipped { get; set; }
    public List<Finding> Findings { get; } = [];
}

// ---- Web -----------------------------------------------------------------------------------------------------------

public sealed record HttpHeader(string Name, string Value);

public sealed class WebReport
{
    public required string Url { get; init; }
    public List<string> Redirects { get; } = [];
    public string? FinalUrl { get; set; }
    public int? Status { get; set; }
    public string? Title { get; set; }
    public string? Server { get; set; }
    public List<HttpHeader> Headers { get; } = [];
    public long? HstsMaxAge { get; set; }
    public string? Error { get; set; }
    public List<Finding> Findings { get; } = [];
}

// ---- Mail ----------------------------------------------------------------------------------------------------------

public sealed class SmtpProbe
{
    public required string Ip { get; init; }
    public string? Banner { get; set; }
    public List<string> Capabilities { get; } = [];
    public bool StartTls { get; set; }
    public string? Error { get; set; }
}

public sealed record TlsaRow(string Name, int Usage, int Selector, int Matching, string Data, bool? Matches);

public sealed class MxHost
{
    public required string Host { get; init; }
    public int Preference { get; init; }
    public List<string> Addresses { get; } = [];
    public string? Service { get; set; }
    public List<SmtpProbe> Smtp { get; } = [];
    public List<TlsaRow> Tlsa { get; } = [];
}

public enum SpfQualifier { Pass, Fail, SoftFail, Neutral }

/// <summary>One term of an SPF record, with what it comes to: the addresses it allows, or the record it brings in.</summary>
public sealed class SpfNode
{
    public required string Term { get; init; }
    public string Mechanism { get; init; } = "";
    public SpfQualifier Qualifier { get; init; }
    public string? Domain { get; set; }
    public string? Record { get; set; }
    public int DnsLookups { get; set; }
    public string? Note { get; set; }
    public string? Error { get; set; }
    public List<string> Networks { get; } = [];
    public List<SpfNode> Children { get; } = [];
}

public sealed record NetworkRoute(string Prefix, long Asn, string? AsName, string? Country, string? Provider);

/// <summary>A network SPF lets send mail, where it was found, and which of its addresses were looked at.</summary>
public sealed class SpfNetwork
{
    public required string Network { get; init; }
    public required string Source { get; init; }
    public double AddressCount { get; init; }
    /// <summary>False when the term isn't a pass, such as <c>-ip4:</c>: listed in the record but not allowed.</summary>
    public bool Allowed { get; init; }
    public List<string> Checked { get; } = [];
    [System.Text.Json.Serialization.JsonIgnore] public bool Sampled => Checked.Count < AddressCount;
    /// <summary>The routed prefixes the network is made of, which between them say the AS and country of all of it.</summary>
    public List<NetworkRoute> Routes { get; } = [];
    public bool RoutesComplete { get; set; } = true;
}

public sealed class SpfReport
{
    public required string Domain { get; init; }
    public string? Record { get; set; }
    public SpfNode? Root { get; set; }
    public List<SpfNetwork> Networks { get; } = [];
    public List<string> Services { get; } = [];
    public int DnsLookups { get; set; }
    public int VoidLookups { get; set; }
    public string? AllTerm { get; set; }
    /// <summary>True when something can only be resolved for one sender, so the list of networks isn't all of it.</summary>
    public bool Incomplete { get; set; }
    public List<Finding> Findings { get; } = [];
}

public sealed class DkimKey
{
    public required string Selector { get; init; }
    public required string Name { get; init; }
    public required string Record { get; init; }
    public string KeyType { get; set; } = "rsa";
    public int Bits { get; set; }
    public bool Revoked { get; set; }
    public bool Testing { get; set; }
    public string? Hashes { get; set; }
    public string? Service { get; set; }
    public string? Problem { get; set; }
}

public sealed class DkimReport
{
    public required string Domain { get; init; }
    public List<DkimKey> Keys { get; } = [];
    public int SelectorsTried { get; set; }
    /// <summary>"none" when <c>_domainkey</c> doesn't exist at all, "some" when it does with nothing at the selectors tried.</summary>
    public string? DomainKeyNode { get; set; }
    public List<Finding> Findings { get; } = [];
}

public sealed class DmarcReport
{
    public required string Domain { get; init; }
    public string? RecordAt { get; set; }
    public string? Record { get; set; }
    public string? Policy { get; set; }
    public string? SubdomainPolicy { get; set; }
    public int Percent { get; set; } = 100;
    public string AlignDkim { get; set; } = "r";
    public string AlignSpf { get; set; } = "r";
    public List<string> AggregateTo { get; } = [];
    public List<string> FailureTo { get; } = [];
    public List<Finding> Findings { get; } = [];
    [System.Text.Json.Serialization.JsonIgnore] public bool Enforcing => Policy is "quarantine" or "reject" && Percent == 100;
}

public sealed class BimiReport
{
    public required string Domain { get; init; }
    public string? RecordAt { get; set; }
    public string? Record { get; set; }
    public string? LogoUrl { get; set; }
    public string? EvidenceUrl { get; set; }
    public int? LogoBytes { get; set; }
    public bool? LogoValid { get; set; }
    public string? LogoSha256 { get; set; }
    public string? CertificateKind { get; set; }
    public string? MarkType { get; set; }
    public bool? CertificateValid { get; set; }
    public bool? LogoMatchesCertificate { get; set; }
    public List<CertificateInfo> Chain { get; } = [];
    public string? ChainDetail { get; set; }
    public List<Finding> Findings { get; } = [];
}

public sealed class MtaStsReport
{
    public required string Domain { get; init; }
    public string? Record { get; set; }
    public string? PolicyUrl { get; set; }
    public string? Mode { get; set; }
    public long? MaxAge { get; set; }
    public List<string> PolicyMx { get; } = [];
    public string? TlsRpt { get; set; }
    public List<Finding> Findings { get; } = [];
}

public sealed class MailReport
{
    public required string Domain { get; init; }
    public List<MxHost> Mx { get; } = [];
    public bool NullMx { get; set; }
    public string? Service { get; set; }
    public SpfReport? Spf { get; set; }
    public DkimReport? Dkim { get; set; }
    public DmarcReport? Dmarc { get; set; }
    public BimiReport? Bimi { get; set; }
    public MtaStsReport? MtaSts { get; set; }
    public List<Finding> Findings { get; } = [];
}

// ---- Blocklists ----------------------------------------------------------------------------------------------------

public enum BlocklistStatus { Clean, Listed, Refused, Failed, NotApplicable }

/// <param name="Policy">The address is listed for what it is (an end-user network, no mail service seen), not for anything it did.</param>
public sealed record BlocklistResult(string Zone, BlocklistStatus Status, string? Codes, string? Reason, bool Policy = false);

public sealed record BlocklistHealth(string Zone, string Name, bool Usable, string Detail);

public sealed class BlocklistReport
{
    public List<BlocklistHealth> Lists { get; } = [];
    public Dictionary<string, List<BlocklistResult>> Results { get; } = [];
    public int Budget { get; set; }
    public int NotChecked { get; set; }
    public List<Finding> Findings { get; } = [];
}

// ---- Cloudflare ----------------------------------------------------------------------------------------------------

public sealed record CloudflareRecord(string Name, string Type, string Content, bool Proxied, int Ttl, int? Priority);

public sealed class CloudflareZone
{
    public required string Name { get; init; }
    public required string Id { get; init; }
    public string? Status { get; init; }
    public string? Plan { get; init; }
    public string? Account { get; init; }
    public IReadOnlyList<string> NameServers { get; init; } = [];
    public List<CloudflareRecord> Records { get; } = [];
}

public sealed class CloudflareReport
{
    public bool Configured { get; set; }
    public List<CloudflareZone> Zones { get; } = [];
    public List<string> Errors { get; } = [];
    public List<Finding> Findings { get; } = [];
}

// ---- Followed domains ----------------------------------------------------------------------------------------------

/// <summary>Another domain found along the way, and the short look that was taken at it.</summary>
public sealed class RelatedDomain
{
    public required string Domain { get; init; }
    public int Depth { get; init; }
    public List<string> Reasons { get; } = [];
    public Registration? Registration { get; set; }
    public List<string> Addresses { get; } = [];
    public List<string> NameServers { get; } = [];
    public List<string> MailHosts { get; } = [];
    public string? Spf { get; set; }
    public string? DmarcPolicy { get; set; }
}

// ---- The whole -----------------------------------------------------------------------------------------------------

public sealed record Step(string Name, string State, string? Detail);

/// <summary>
/// What's known so far about the target. The lookup's tasks fill it in as they finish, each taking <see cref="Sync"/>
/// through <see cref="Change"/>, and whatever reads it (a page, an export) takes <see cref="Sync"/> too.
/// </summary>
public sealed class Dossier
{
    public required Target Target { get; init; }
    public DateTimeOffset Started { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? Finished { get; set; }
    public string? MailDomain { get; set; }
    public Registration? Registration { get; set; }
    public DnsReport Dns { get; } = new();
    public Dictionary<string, AddressInfo> Addresses { get; } = new(StringComparer.Ordinal);
    public List<TlsReport> Tls { get; } = [];
    public List<PortReport> Ports { get; } = [];
    public List<WebReport> Web { get; } = [];
    public MailReport? Mail { get; set; }
    public BlocklistReport Blocklists { get; } = new();
    public CloudflareReport Cloudflare { get; } = new();
    public List<RelatedDomain> Related { get; } = [];
    public List<Step> Steps { get; } = [];
    public List<Finding> Notes { get; } = [];
    /// <summary>Raised on the task that made the change. Goes up by one each time.</summary>
    [System.Text.Json.Serialization.JsonIgnore] public int Revision { get; private set; }

    [System.Text.Json.Serialization.JsonIgnore]
    public object Sync { get; } = new();

    public event Action? Changed;

    public void Change(Action change)
    {
        lock (Sync)
        {
            change();
            Revision++;
        }
        Changed?.Invoke();
    }

    public T Read<T>(Func<T> read)
    {
        lock (Sync) return read();
    }
}
