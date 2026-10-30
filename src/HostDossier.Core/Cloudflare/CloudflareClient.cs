using System.Net.Http.Headers;
using System.Text.Json;

namespace Strongthium.HostDossier;

/// <summary>
/// Cloudflare's API, read only: with a token of yours (Zone Read and DNS Read are enough) it finds the zones the token
/// can see and reads their DNS records as they're stored, so a proxied record shows the real address behind Cloudflare,
/// which the public DNS never does. The token goes only to api.cloudflare.com.
/// </summary>
public sealed class CloudflareClient(HttpClient http, string token)
{
    private const string Api = "https://api.cloudflare.com/client/v4/";

    /// <summary>The zone with this exact name, when the token can see it.</summary>
    public async Task<CloudflareZone?> FindZoneAsync(string name, CancellationToken cancel)
    {
        using var document = await GetAsync($"zones?name={Uri.EscapeDataString(name)}", cancel).ConfigureAwait(false);
        foreach (var zone in document.RootElement.GetProperty("result").EnumerateArray())
        {
            return ReadZone(zone);
        }
        return null;
    }

    /// <summary>Every zone the token can see, for showing in the settings that a token works.</summary>
    public async Task<List<string>> ListZonesAsync(CancellationToken cancel)
    {
        var names = new List<string>();
        for (var page = 1; page < 100; page++)
        {
            using var document = await GetAsync($"zones?per_page=50&page={page}", cancel).ConfigureAwait(false);
            foreach (var zone in document.RootElement.GetProperty("result").EnumerateArray())
            {
                if (zone.GetProperty("name").GetString() is { } name) names.Add(name);
            }
            if (!MorePages(document.RootElement, page)) break;
        }
        return names;
    }

    public async Task ReadRecordsAsync(CloudflareZone zone, CancellationToken cancel)
    {
        for (var page = 1; page < 1000; page++)
        {
            using var document = await GetAsync($"zones/{zone.Id}/dns_records?per_page=500&page={page}", cancel).ConfigureAwait(false);
            foreach (var record in document.RootElement.GetProperty("result").EnumerateArray())
            {
                zone.Records.Add(ReadRecord(record));
            }
            if (!MorePages(document.RootElement, page)) break;
        }
    }

    private static bool MorePages(JsonElement root, int page) =>
        root.TryGetProperty("result_info", out var info) && info.TryGetProperty("total_pages", out var pages) && pages.ValueKind == JsonValueKind.Number && page < pages.GetInt32();

    internal static CloudflareZone ReadZone(JsonElement zone) => new()
    {
        Name = zone.GetProperty("name").GetString() ?? "",
        Id = zone.GetProperty("id").GetString() ?? "",
        Status = Text(zone, "status"),
        Plan = zone.TryGetProperty("plan", out var plan) ? Text(plan, "name") : null,
        Account = zone.TryGetProperty("account", out var account) ? Text(account, "name") : null,
        NameServers = zone.TryGetProperty("name_servers", out var servers) && servers.ValueKind == JsonValueKind.Array
            ? servers.EnumerateArray().Select(s => s.GetString() ?? "").ToList()
            : [],
    };

    internal static CloudflareRecord ReadRecord(JsonElement record) => new(
        Text(record, "name")?.ToLowerInvariant() ?? "",
        Text(record, "type") ?? "",
        Text(record, "content") ?? "",
        record.TryGetProperty("proxied", out var proxied) && proxied.ValueKind == JsonValueKind.True,
        record.TryGetProperty("ttl", out var ttl) && ttl.ValueKind == JsonValueKind.Number ? ttl.GetInt32() : 0,
        record.TryGetProperty("priority", out var priority) && priority.ValueKind == JsonValueKind.Number ? priority.GetInt32() : null);

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private async Task<JsonDocument> GetAsync(string path, CancellationToken cancel)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        using var request = new HttpRequestMessage(HttpMethod.Get, Api + path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await http.SendAsync(request, timeout.Token).ConfigureAwait(false);
        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        JsonDocument document;
        try
        {
            document = await JsonDocument.ParseAsync(stream, cancellationToken: timeout.Token).ConfigureAwait(false);
        }
        catch (JsonException)
        {
            throw new HttpRequestException($"Cloudflare answered {(int)response.StatusCode} with something that isn't its API.");
        }
        if (!response.IsSuccessStatusCode || !document.RootElement.TryGetProperty("success", out var success) || success.ValueKind != JsonValueKind.True)
        {
            var message = ErrorText(document.RootElement);
            document.Dispose();
            throw new HttpRequestException($"Cloudflare: {message} ({(int)response.StatusCode})");
        }
        return document;
    }

    private static string ErrorText(JsonElement root)
    {
        if (root.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Array)
        {
            var messages = errors.EnumerateArray().Select(e => Text(e, "message")).OfType<string>().ToList();
            if (messages.Count > 0) return string.Join("; ", messages);
        }
        return "the request failed";
    }
}
