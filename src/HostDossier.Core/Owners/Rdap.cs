using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Strongthium.HostDossier;

/// <summary>
/// RDAP, the registries' structured successor to WHOIS. IANA's bootstrap files say which server knows each top-level
/// domain and address block; a registry's answer may link on to the registrar's, which knows more.
/// </summary>
public sealed class Rdap(HttpClient http)
{
    private readonly Dictionary<string, Task<JsonDocument?>> bootstrap = [];

    private Task<JsonDocument?> BootstrapAsync(string file, CancellationToken cancel)
    {
        lock (bootstrap)
        {
            if (!bootstrap.TryGetValue(file, out var task))
            {
                bootstrap[file] = task = ReadAsync($"https://data.iana.org/rdap/{file}.json", cancel);
            }
            return task;
        }
    }

    private async Task<JsonDocument?> ReadAsync(string url, CancellationToken cancel)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/rdap+json"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await http.SendAsync(request, timeout.Token).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.NotFound) return null;
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
            return await JsonDocument.ParseAsync(stream, cancellationToken: timeout.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or IOException
            || (exception is OperationCanceledException && !cancel.IsCancellationRequested))
        {
            return null;
        }
    }

    // ---- Which server --------------------------------------------------------------------------------------------

    private async Task<string?> DomainServerAsync(string domain, CancellationToken cancel)
    {
        var document = await BootstrapAsync("dns", cancel).ConfigureAwait(false);
        if (document is null) return null;
        var labels = domain.Split('.');
        for (var i = 0; i < labels.Length; i++)
        {
            var suffix = string.Join('.', labels[i..]);
            foreach (var service in document.RootElement.GetProperty("services").EnumerateArray())
            {
                if (service[0].EnumerateArray().Any(e => string.Equals(e.GetString(), suffix, StringComparison.OrdinalIgnoreCase))) return FirstUrl(service);
            }
        }
        return null;
    }

    private async Task<string?> AddressServerAsync(string ip, CancellationToken cancel)
    {
        var v6 = ip.Contains(':');
        var document = await BootstrapAsync(v6 ? "ipv6" : "ipv4", cancel).ConfigureAwait(false);
        if (document is null) return null;
        string? best = null;
        var bestLength = -1;
        foreach (var service in document.RootElement.GetProperty("services").EnumerateArray())
        {
            foreach (var entry in service[0].EnumerateArray())
            {
                var network = entry.GetString();
                if (network is null) continue;
                // IPv4 ranges in the file can be "192.0.0.0/8" or "1.0.0.0/8": all are networks.
                if (Names.NetworkContains(network, ip) && network.Split('/') is [_, var length] && int.Parse(length, System.Globalization.CultureInfo.InvariantCulture) > bestLength)
                {
                    bestLength = int.Parse(length, System.Globalization.CultureInfo.InvariantCulture);
                    best = FirstUrl(service);
                }
            }
        }
        return best;
    }

    private static string? FirstUrl(JsonElement service)
    {
        string? fallback = null;
        foreach (var url in service[1].EnumerateArray())
        {
            var text = url.GetString();
            if (text is null) continue;
            if (text.StartsWith("https:", StringComparison.OrdinalIgnoreCase)) return text.TrimEnd('/') + "/";
            fallback ??= text.TrimEnd('/') + "/";
        }
        return fallback;
    }

    // ---- Domains ---------------------------------------------------------------------------------------------------

    /// <summary>Fills a registration from RDAP. False when no RDAP server has the domain.</summary>
    public async Task<bool> DomainAsync(Registration registration, CancellationToken cancel)
    {
        var server = await DomainServerAsync(registration.Domain, cancel).ConfigureAwait(false);
        if (server is null) return false;
        using var document = await ReadAsync($"{server}domain/{registration.Domain}", cancel).ConfigureAwait(false);
        if (document is null) return false;
        ReadDomain(registration, document.RootElement);
        registration.Source = "RDAP";

        // The registry often only knows the registrar: the registrar's own server knows the contacts.
        if (FollowLink(document.RootElement) is { } link)
        {
            using var more = await ReadAsync(link, cancel).ConfigureAwait(false);
            if (more is not null) ReadDomain(registration, more.RootElement);
        }
        return true;
    }

    internal static void ReadDomain(Registration registration, JsonElement root)
    {
        foreach (var status in Strings(root, "status"))
        {
            if (!registration.Statuses.Contains(status, StringComparer.OrdinalIgnoreCase)) registration.Statuses.Add(status);
        }
        foreach (var (action, date) in Events(root))
        {
            switch (action)
            {
                case "registration": registration.Created ??= date; break;
                case "last changed": registration.Updated ??= date; break;
                case "expiration": registration.Expires ??= date; break;
            }
        }
        if (root.TryGetProperty("nameservers", out var servers) && servers.ValueKind == JsonValueKind.Array)
        {
            foreach (var server in servers.EnumerateArray())
            {
                var name = Names.NormalizeName(Text(server, "ldhName"));
                if (name is not null && !registration.NameServers.Contains(name)) registration.NameServers.Add(name);
            }
        }
        if (root.TryGetProperty("secureDNS", out var secure) && secure.TryGetProperty("delegationSigned", out var signed) && signed.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            registration.DnssecSigned ??= signed.GetBoolean();
        }
        foreach (var (roles, entity) in Entities(root))
        {
            var contact = ReadContact(entity, roles);
            if (roles.Contains("registrar"))
            {
                registration.Registrar ??= contact.Organization ?? contact.Name;
                if (entity.TryGetProperty("publicIds", out var ids) && ids.ValueKind == JsonValueKind.Array)
                {
                    foreach (var id in ids.EnumerateArray()) registration.RegistrarId ??= Text(id, "identifier");
                }
                registration.RegistrarUrl ??= Link(entity);
            }
            else if (roles.Contains("abuse"))
            {
                registration.AbuseEmail ??= contact.Email;
                registration.AbusePhone ??= contact.Phone;
            }
            else if (contact.Name is not null || contact.Organization is not null || contact.Email is not null)
            {
                var existing = registration.Contacts.FindIndex(c => c.Role == contact.Role);
                if (existing < 0) registration.Contacts.Add(contact);
            }
        }
    }

    private static string? FollowLink(JsonElement root)
    {
        if (!root.TryGetProperty("links", out var links) || links.ValueKind != JsonValueKind.Array) return null;
        var self = Text(root, "handle");
        foreach (var link in links.EnumerateArray())
        {
            if (Text(link, "rel") == "related" && Text(link, "href") is { } href && (Text(link, "type")?.Contains("rdap", StringComparison.OrdinalIgnoreCase) ?? href.Contains("/domain/", StringComparison.OrdinalIgnoreCase)))
            {
                _ = self;
                return href;
            }
        }
        return null;
    }

    // ---- Addresses -------------------------------------------------------------------------------------------------

    public async Task<NetworkOwner> AddressAsync(string ip, CancellationToken cancel)
    {
        var owner = new NetworkOwner();
        var server = await AddressServerAsync(ip, cancel).ConfigureAwait(false);
        if (server is null)
        {
            owner.Error = "No RDAP server is listed for this address.";
            return owner;
        }
        using var document = await ReadAsync($"{server}ip/{ip}", cancel).ConfigureAwait(false);
        if (document is null)
        {
            owner.Error = $"{new Uri(server).Host} had no answer for it.";
            return owner;
        }
        ReadNetwork(owner, document.RootElement);
        return owner;
    }

    internal static void ReadNetwork(NetworkOwner owner, JsonElement root)
    {
        owner.Handle = Text(root, "handle");
        owner.Name = Text(root, "name");
        owner.Type = Text(root, "type");
        owner.Country = Text(root, "country")?.ToUpperInvariant();
        if (root.TryGetProperty("cidr0_cidrs", out var cidrs) && cidrs.ValueKind == JsonValueKind.Array && cidrs.GetArrayLength() > 0)
        {
            owner.Range = string.Join(", ", cidrs.EnumerateArray().Select(c => $"{Text(c, "v4prefix") ?? Text(c, "v6prefix")}/{(c.TryGetProperty("length", out var l) ? l.GetInt32() : 0)}"));
        }
        else if (Text(root, "startAddress") is { } start)
        {
            owner.Range = $"{start} - {Text(root, "endAddress")}";
        }
        foreach (var (action, date) in Events(root))
        {
            if (action == "registration") owner.Registered ??= date;
            else if (action == "last changed") owner.Updated ??= date;
        }
        foreach (var (roles, entity) in Entities(root))
        {
            var contact = ReadContact(entity, roles);
            if (roles.Contains("abuse")) owner.AbuseEmail ??= contact.Email;
            if (roles.Contains("registrant")) owner.Organization ??= contact.Organization ?? contact.Name;
            owner.Contacts.Add(contact);
        }
        owner.Organization ??= owner.Contacts.Find(c => c.Role.Contains("administrative") || c.Role.Contains("technical"))?.Organization;
    }

    // ---- JSON -------------------------------------------------------------------------------------------------------

    private static string? Text(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static IEnumerable<string> Strings(JsonElement element, string name)
    {
        if (element.TryGetProperty(name, out var array) && array.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in array.EnumerateArray())
            {
                if (item.GetString() is { } text) yield return text;
            }
        }
    }

    private static IEnumerable<(string Action, DateTimeOffset Date)> Events(JsonElement element)
    {
        if (!element.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Array) yield break;
        foreach (var item in events.EnumerateArray())
        {
            if (Text(item, "eventAction") is { } action && DateTimeOffset.TryParse(Text(item, "eventDate"), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var date))
            {
                yield return (action, date);
            }
        }
    }

    /// <summary>An entity and those inside it (a registrar's abuse contact is inside the registrar).</summary>
    private static IEnumerable<(HashSet<string> Roles, JsonElement Entity)> Entities(JsonElement element)
    {
        if (!element.TryGetProperty("entities", out var entities) || entities.ValueKind != JsonValueKind.Array) yield break;
        foreach (var entity in entities.EnumerateArray())
        {
            var roles = Strings(entity, "roles").Select(r => r.ToLowerInvariant()).ToHashSet();
            yield return (roles, entity);
            foreach (var inner in Entities(entity)) yield return inner;
        }
    }

    private static string? Link(JsonElement entity)
    {
        if (!entity.TryGetProperty("links", out var links) || links.ValueKind != JsonValueKind.Array) return null;
        foreach (var link in links.EnumerateArray())
        {
            if (Text(link, "rel") == "about" && Text(link, "href") is { } href) return href;
        }
        return null;
    }

    /// <summary>A contact's jCard (RFC 7095): an array of [name, parameters, type, value] for each property.</summary>
    private static Contact ReadContact(JsonElement entity, HashSet<string> roles)
    {
        string? name = null, org = null, email = null, phone = null, address = null, country = null;
        if (entity.TryGetProperty("vcardArray", out var vcard) && vcard.ValueKind == JsonValueKind.Array && vcard.GetArrayLength() >= 2)
        {
            foreach (var property in vcard[1].EnumerateArray())
            {
                if (property.GetArrayLength() < 4) continue;
                var value = property[3];
                switch (property[0].GetString())
                {
                    case "fn": name = Plain(value); break;
                    case "org": org = value.ValueKind == JsonValueKind.Array ? string.Join(" ", value.EnumerateArray().Select(Plain)) : Plain(value); break;
                    case "email": email ??= Plain(value); break;
                    case "tel": phone ??= Plain(value)?.Replace("tel:", "", StringComparison.OrdinalIgnoreCase); break;
                    case "adr":
                        if (value.ValueKind == JsonValueKind.Array)
                        {
                            var parts = value.EnumerateArray().Select(Plain).Where(p => !string.IsNullOrWhiteSpace(p)).ToList();
                            if (parts.Count > 0) { address = string.Join(", ", parts); country = parts[^1]; }
                        }
                        if (property[1].ValueKind == JsonValueKind.Object && Text(property[1], "label") is { } label) address ??= label.Replace("\n", ", ");
                        break;
                }
            }
        }
        // A person's name in "fn" may be the organization: RIRs only fill in fn for organizations.
        org ??= entity.TryGetProperty("handle", out _) && roles.Contains("registrant") ? name : null;
        return new Contact(string.Join(", ", roles.Order(StringComparer.Ordinal)), name, org, email, phone, address, country);
    }

    private static string? Plain(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString(),
        JsonValueKind.Array => string.Join(" ", element.EnumerateArray().Select(Plain).Where(p => !string.IsNullOrEmpty(p))),
        _ => null,
    };
}
