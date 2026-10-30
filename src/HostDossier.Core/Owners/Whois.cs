using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Strongthium.HostDossier;

/// <summary>
/// WHOIS on port 43: IANA says which server knows the top-level domain or the address block, that server may refer on
/// to the registrar's or another registry's, and every answer on the way is kept.
/// </summary>
public static partial class Whois
{
    private const string Root = "whois.iana.org";
    private const int MaxBytes = 256 * 1024;

    public static async Task<List<WhoisResponse>> LookUpAsync(string query, CancellationToken cancel)
    {
        var responses = new List<WhoisResponse>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var isAddress = Names.IsAddress(query);
        var server = Root;
        for (var hop = 0; hop < 4 && server is not null && visited.Add(server); hop++)
        {
            string text;
            try
            {
                text = await QueryAsync(server, Phrase(server, query, isAddress), cancel).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is SocketException or IOException or TimeoutException or OperationCanceledException && !cancel.IsCancellationRequested)
            {
                responses.Add(new WhoisResponse(server, "No answer: " + exception.Message));
                break;
            }
            responses.Add(new WhoisResponse(server, text));
            server = Referral(text);
        }
        return responses;
    }

    /// <summary>What to send: some servers want more than the bare name for the whole answer in English.</summary>
    internal static string Phrase(string server, string query, bool isAddress) => server.ToLowerInvariant() switch
    {
        "whois.arin.net" when isAddress => $"n + {query}",
        "whois.denic.de" => $"-T dn,ace {query}",
        "whois.jprs.jp" => $"{query}/e",
        "whois.nic.ad.jp" => $"{query} /e",
        "whois.verisign-grs.com" or "whois.crsnic.net" => $"domain {query}",
        _ => query,
    };

    internal static string? Referral(string text)
    {
        foreach (var line in text.AsSpan().EnumerateLines())
        {
            var match = ReferralLine().Match(line.ToString());
            if (!match.Success) continue;
            var server = match.Groups[1].Value.Trim().TrimEnd('/');
            var scheme = server.IndexOf("://", StringComparison.Ordinal);
            if (scheme >= 0) server = server[(scheme + 3)..];
            var port = server.IndexOf(':');
            if (port >= 0) server = server[..port];
            // A web address given as the registrar's "WHOIS server" can't be asked on port 43.
            if (server.Length > 0 && !server.Contains(' ') && server.Contains('.')) return server;
        }
        return null;
    }

    [GeneratedRegex(@"^\s*(?:refer|whois|ReferralServer|Registrar WHOIS Server|Whois Server|ResourceLink)\s*:\s*(\S+)\s*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ReferralLine();

    private static async Task<string> QueryAsync(string server, string query, CancellationToken cancel)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(TimeSpan.FromSeconds(12));
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(server, 43, timeout.Token).ConfigureAwait(false);
            await using var stream = client.GetStream();
            await stream.WriteAsync(Encoding.ASCII.GetBytes(query + "\r\n"), timeout.Token).ConfigureAwait(false);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int read;
            while (buffer.Length < MaxBytes && (read = await stream.ReadAsync(chunk, timeout.Token).ConfigureAwait(false)) > 0)
            {
                buffer.Write(chunk, 0, read);
            }
            return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length).Replace("\r\n", "\n").Trim();
        }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
        {
            throw new TimeoutException($"{server} didn't answer in time.");
        }
    }

    /// <summary>Fills in what RDAP didn't give from the plain text of the WHOIS answers, the last and most specific
    /// first. Every server has its own format, so only the common labels are read.</summary>
    public static void FillIn(Registration registration)
    {
        foreach (var response in Enumerable.Reverse(registration.Whois))
        {
            foreach (var line in response.Text.Split('\n'))
            {
                var colon = line.IndexOf(':');
                if (colon <= 0) continue;
                var label = line[..colon].Trim().ToLowerInvariant();
                var value = line[(colon + 1)..].Trim();
                if (value.Length == 0) continue;
                switch (label)
                {
                    case "registrar" or "sponsoring registrar" or "registrar name": registration.Registrar ??= value; break;
                    case "registrar iana id": registration.RegistrarId ??= value; break;
                    case "registrar url": registration.RegistrarUrl ??= value; break;
                    case "creation date" or "created" or "created on" or "registered on" or "registered" or "registration time":
                        registration.Created ??= ParseDate(value);
                        break;
                    case "updated date" or "last updated" or "last modified" or "changed" or "modified":
                        registration.Updated ??= ParseDate(value);
                        break;
                    case "registry expiry date" or "registrar registration expiration date" or "expiry date" or "expires" or "expires on" or "expiration date" or "paid-till" or "expiration time":
                        registration.Expires ??= ParseDate(value);
                        break;
                    case "domain status" or "status":
                        var status = value.Split(' ')[0];
                        if (!registration.Statuses.Contains(status, StringComparer.OrdinalIgnoreCase)) registration.Statuses.Add(status);
                        break;
                    case "name server" or "nameserver" or "nserver" or "name servers":
                        var server = Names.NormalizeName(value.Split(' ')[0]);
                        if (server is not null && !registration.NameServers.Contains(server)) registration.NameServers.Add(server);
                        break;
                    case "registrar abuse contact email": registration.AbuseEmail ??= value; break;
                    case "registrar abuse contact phone": registration.AbusePhone ??= value; break;
                    case "dnssec":
                        registration.DnssecSigned ??= value.StartsWith("signed", StringComparison.OrdinalIgnoreCase) && !value.Contains("unsigned", StringComparison.OrdinalIgnoreCase);
                        break;
                }
            }
            ReadContact(registration, response.Text, "Registrant");
            ReadContact(registration, response.Text, "Admin");
            ReadContact(registration, response.Text, "Tech");
        }
        registration.Source ??= registration.Whois.Count > 0 ? "WHOIS" : null;
    }

    private static void ReadContact(Registration registration, string text, string role)
    {
        if (registration.Contacts.Exists(c => string.Equals(c.Role, role, StringComparison.OrdinalIgnoreCase))) return;
        string? Field(string name)
        {
            var match = Regex.Match(text, $@"^\s*{role} {name}\s*:\s*(.+?)\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            return match.Success ? match.Groups[1].Value : null;
        }
        var contact = new Contact(role.ToLowerInvariant(), Field("Name"), Field("Organi[sz]ation"), Field("Email"), Field("Phone"),
            string.Join(", ", new[] { Field("Street"), Field("City"), Field("State/Province"), Field("Postal Code") }.Where(s => !string.IsNullOrEmpty(s))) is { Length: > 0 } address ? address : null,
            Field("Country"));
        if (contact.Name is not null || contact.Organization is not null || contact.Email is not null) registration.Contacts.Add(contact);
    }

    internal static DateTimeOffset? ParseDate(string value)
    {
        var text = value.Trim();
        var space = text.IndexOf(" (", StringComparison.Ordinal);
        if (space > 0) text = text[..space];
        text = text.Replace(" UTC", "Z", StringComparison.OrdinalIgnoreCase).Replace(" GMT", "Z", StringComparison.OrdinalIgnoreCase);
        if (DateTimeOffset.TryParse(text, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var date)) return date;
        string[] formats = ["dd-MMM-yyyy", "dd.MM.yyyy", "yyyy.MM.dd", "yyyy/MM/dd", "dd/MM/yyyy", "yyyyMMdd", "yyyy-MM-dd HH:mm:ss", "dd-MM-yyyy"];
        return DateTimeOffset.TryParseExact(text, formats, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out date) ? date : null;
    }
}
