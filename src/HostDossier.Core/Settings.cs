using System.Text.Json;
using System.Text.Json.Serialization;

namespace Strongthium.HostDossier;

/// <summary>A blocklist that's queried by DNS.</summary>
public sealed class BlocklistEntry
{
    public string Zone { get; set; } = "";
    public string Name { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public bool Ipv6 { get; set; }
    public string? Note { get; set; }
}

/// <summary>A Cloudflare API token. <see cref="Protected"/> is the token as Windows encrypted it for this user: the
/// plain token is never written to a file.</summary>
public sealed class CloudflareAccount
{
    public string Name { get; set; } = "";
    public string Protected { get; set; } = "";
    /// <summary>Set in memory only, when the token has been decrypted or was given on the command line.</summary>
    [JsonIgnore] public string? Token { get; set; }
}

/// <summary>What a lookup does. Saved as JSON by the program; the defaults are what a new installation gets.</summary>
public sealed class Settings
{
    // What to do
    public bool Registration { get; set; } = true;
    public bool Dns { get; set; } = true;
    public bool Tls { get; set; } = true;
    public bool Ports { get; set; } = true;
    public bool Web { get; set; } = true;
    public bool Mail { get; set; } = true;
    public bool Blocklists { get; set; } = true;
    public bool CertificateLogs { get; set; } = true;
    public bool FollowRelated { get; set; } = true;

    // How far to go
    public int FollowDepth { get; set; } = 2;
    public int FollowLimit { get; set; } = 40;
    /// <summary>How many addresses of a name get a thorough TLS test. Others on the same name aren't tested.</summary>
    public int TlsAddresses { get; set; } = 2;
    /// <summary>How many addresses get their ports scanned.</summary>
    public int PortScanAddresses { get; set; } = 8;
    /// <summary>A network in SPF of up to this many addresses gets every one looked up: AS, country, reverse name.</summary>
    public int WholeNetworkUpTo { get; set; } = 1024;
    /// <summary>A bigger network gets reverse names for this many addresses, spread across it. The AS and country of all
    /// of it come from its routed prefixes.</summary>
    public int SampleSize { get; set; } = 8;
    /// <summary>How many SPF addresses in all get a reverse lookup. The domain's own networks go first, then the smallest.</summary>
    public int MailAddressLookups { get; set; } = 4096;
    /// <summary>How many of them are checked against the blocklists, which is many queries each.</summary>
    public int MailAddressBudget { get; set; } = 400;

    /// <summary>Keep the last report of everything looked up, in <see cref="ReportCache.DefaultDirectory"/>.</summary>
    public bool KeepReports { get; set; } = true;
    /// <summary>Looking up something with a kept report younger than this shows that report. 0 always looks it up.</summary>
    public int CacheHours { get; set; } = 24;
    /// <summary>Also scan addresses of a content network, where the ports answer for the network, not the site.</summary>
    public bool ScanCdnAddresses { get; set; }

    // Port scanning
    public string PortList { get; set; } = PortCatalog.DefaultList;
    public int PortConcurrency { get; set; } = 48;
    public int PortTimeoutMs { get; set; } = 2500;

    /// <summary>The DNS servers to ask; empty means the computer's own. Public ones by default: a research tool wants the
    /// answers the rest of the internet gets, and a small office or home DNS server can be slow, or lose long answers.
    /// What's asked about goes to these servers.</summary>
    public List<string> Resolvers { get; set; } = ["1.1.1.1", "8.8.8.8"];
    public List<string> DkimSelectors { get; set; } = [.. DkimCheck.DefaultSelectors];
    public List<BlocklistEntry> BlocklistEntries { get; set; } = BlocklistCheck.DefaultLists();

    public List<CloudflareAccount> CloudflareAccounts { get; set; } = [];

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static string DefaultDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Strongthium", "host-dossier");

    public static Settings Load(string file)
    {
        try
        {
            if (File.Exists(file) && JsonSerializer.Deserialize<Settings>(File.ReadAllText(file), Json) is { } settings) return settings;
        }
        catch (Exception exception) when (exception is IOException or JsonException or UnauthorizedAccessException)
        {
            // A file that can't be read is the same as none: the defaults are used, and saving replaces it.
        }
        return new Settings();
    }

    public void Save(string file)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        var part = file + ".part";
        File.WriteAllText(part, JsonSerializer.Serialize(this, Json));
        File.Move(part, file, overwrite: true);
    }
}
