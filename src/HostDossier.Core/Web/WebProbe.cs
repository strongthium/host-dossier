using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace Strongthium.HostDossier;

/// <summary>What a site's web server says: where it redirects to, what it runs on, its security headers.</summary>
public sealed partial class WebProbe(HttpClient http)
{
    private const int MaxBody = 256 * 1024;

    public async Task<WebReport> FetchAsync(string url, CancellationToken cancel)
    {
        var report = new WebReport { Url = url };
        var current = new Uri(url);
        try
        {
            for (var hop = 0; hop < 8; hop++)
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
                timeout.CancelAfter(TimeSpan.FromSeconds(12));
                using var response = await http.GetAsync(current, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
                report.Status = (int)response.StatusCode;
                report.FinalUrl = current.ToString();
                if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is { } location)
                {
                    current = location.IsAbsoluteUri ? location : new Uri(current, location);
                    report.Redirects.Add(current.ToString());
                    continue;
                }
                report.Headers.Clear();
                foreach (var (name, values) in response.Headers) report.Headers.Add(new HttpHeader(name, string.Join(", ", values)));
                foreach (var (name, values) in response.Content.Headers) report.Headers.Add(new HttpHeader(name, string.Join(", ", values)));
                report.Server = Header(report, "Server");
                var body = await ReadBodyAsync(response, timeout.Token).ConfigureAwait(false);
                var title = TitleTag().Match(body);
                if (title.Success) report.Title = WebUtility.HtmlDecode(Regex.Replace(title.Groups[1].Value, @"\s+", " ")).Trim();
                break;
            }
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or UriFormatException or OperationCanceledException && !cancel.IsCancellationRequested)
        {
            report.Error = exception is OperationCanceledException ? "No answer in time." : exception.GetBaseException().Message;
            return report;
        }
        Judge(report);
        return report;
    }

    private static async Task<string> ReadBodyAsync(HttpResponseMessage response, CancellationToken cancel)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancel).ConfigureAwait(false);
        var buffer = new byte[MaxBody];
        var read = await stream.ReadAtLeastAsync(buffer, MaxBody, throwOnEndOfStream: false, cancel).ConfigureAwait(false);
        return Encoding.UTF8.GetString(buffer, 0, read);
    }

    private static string? Header(WebReport report, string name) =>
        report.Headers.Find(h => string.Equals(h.Name, name, StringComparison.OrdinalIgnoreCase))?.Value;

    private static void Judge(WebReport report)
    {
        void Say(Level level, string text) => report.Findings.Add(new Finding(level, "Web", text));
        var isHttps = report.FinalUrl?.StartsWith("https:", StringComparison.OrdinalIgnoreCase) == true;
        var hsts = Header(report, "Strict-Transport-Security");
        if (hsts is not null)
        {
            var match = Regex.Match(hsts, @"max-age\s*=\s*""?(\d+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (match.Success && long.TryParse(match.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var age))
            {
                report.HstsMaxAge = age;
                if (age >= 15_552_000) Say(Level.Good, $"HSTS is on for {age / 86400} days{(hsts.Contains("preload", StringComparison.OrdinalIgnoreCase) ? ", and asks to be preloaded" : "")}.");
                else if (age == 0) Say(Level.Notice, "HSTS is explicitly turned off (max-age=0).");
                else Say(Level.Notice, $"HSTS is on, but for only {age / 86400} days. Six months is the usual minimum.");
            }
        }
        else if (isHttps)
        {
            Say(Level.Notice, "No HSTS: browsers aren't told to always use HTTPS here.");
        }
        if (isHttps)
        {
            if (Header(report, "Content-Security-Policy") is null) Say(Level.Info, "No Content-Security-Policy header.");
            if (Header(report, "X-Content-Type-Options") is null) Say(Level.Info, "No X-Content-Type-Options header.");
        }
        if (Header(report, "X-Powered-By") is { } powered) Say(Level.Info, $"Announces what it runs on: X-Powered-By: {powered}.");
    }

    [GeneratedRegex(@"<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex TitleTag();
}
