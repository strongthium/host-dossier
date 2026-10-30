using Strongthium.HostDossier;

const string Usage = """
    host-dossier-cli <domain or address> [options]

      --json                  everything found, as JSON (otherwise a Markdown report)
      --out <file>            write it to a file rather than the screen
      --only <list>           do only these: registration,dns,tls,ports,web,mail,blocklists,related
      --skip <list>           leave these out, from the same list
      --depth <n>             how many steps to follow related domains (default 2)
      --ports <list>          the ports to scan: 22,80,8000-8010
      --resolver <address>    the DNS server to ask, again for each one; "system" for this computer's
                              (default: 1.1.1.1 and 8.8.8.8)
      --quiet                 say nothing on the way

    A Cloudflare API token in the environment variable CLOUDFLARE_API_TOKEN is used for zones it can see.
    """;

string? target = null;
var json = false;
var quiet = false;
string? output = null;
var settings = new Settings();
var ownResolvers = false;

for (var i = 0; i < args.Length; i++)
{
    string Next() => ++i < args.Length ? args[i] : throw new ArgumentException($"{args[i - 1]} needs a value.");
    try
    {
        switch (args[i])
        {
            case "--help" or "-h" or "/?":
                Console.WriteLine(Usage);
                return 0;
            case "--json": json = true; break;
            case "--quiet": quiet = true; break;
            case "--out": output = Next(); break;
            case "--depth": settings.FollowDepth = int.Parse(Next(), System.Globalization.CultureInfo.InvariantCulture); break;
            case "--ports": settings.PortList = Next(); break;
            case "--resolver":
                if (!ownResolvers) settings.Resolvers.Clear();
                ownResolvers = true;
                var server = Next();
                if (!server.Equals("system", StringComparison.OrdinalIgnoreCase)) settings.Resolvers.Add(server);
                break;
            case "--only":
                var only = Next().Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.OrdinalIgnoreCase);
                Turn(settings, name => only.Contains(name));
                break;
            case "--skip":
                var skip = Next().Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.OrdinalIgnoreCase);
                Turn(settings, name => !skip.Contains(name));
                break;
            default:
                if (args[i].StartsWith('-')) throw new ArgumentException($"Unknown option: {args[i]}");
                target = args[i];
                break;
        }
    }
    catch (Exception exception) when (exception is ArgumentException or FormatException)
    {
        Console.Error.WriteLine(exception.Message);
        return 2;
    }
}

if (target is null)
{
    Console.Error.WriteLine(Usage);
    return 2;
}
var parsed = Names.ParseTarget(target, out var problem);
if (parsed is null)
{
    Console.Error.WriteLine(problem);
    return 2;
}

if (Environment.GetEnvironmentVariable("CLOUDFLARE_API_TOKEN") is { Length: > 0 } token)
{
    settings.CloudflareAccounts.Add(new CloudflareAccount { Name = "CLOUDFLARE_API_TOKEN", Token = token });
}

using var cancel = new CancellationTokenSource();
Console.CancelKeyPress += (_, stop) =>
{
    stop.Cancel = true;
    cancel.Cancel();
};

var dossier = Lookup.Begin(parsed);
if (!quiet)
{
    var reported = new HashSet<string>();
    dossier.Changed += () =>
    {
        foreach (var step in dossier.Read(() => dossier.Steps.ToList()))
        {
            var line = $"{step.Name}: {step.State}{(step.Detail is { } detail ? $" ({detail})" : "")}";
            lock (reported)
            {
                if (reported.Add(line)) Console.Error.WriteLine($"{DateTime.Now:HH:mm:ss} {line}");
            }
        }
    };
}
using (var lookup = new Lookup(settings))
{
    await lookup.RunAsync(dossier, cancel.Token);
}

var report = json ? Export.ToJson(dossier) : Export.ToMarkdown(dossier);
if (output is not null) File.WriteAllText(output, report);
else Console.Out.WriteLine(report);
return 0;

static void Turn(Settings settings, Func<string, bool> on)
{
    settings.Registration = on("registration");
    settings.Dns = on("dns");
    settings.Tls = on("tls");
    settings.Ports = on("ports");
    settings.Web = on("web");
    settings.Mail = on("mail");
    settings.Blocklists = on("blocklists");
    settings.FollowRelated = on("related");
}
