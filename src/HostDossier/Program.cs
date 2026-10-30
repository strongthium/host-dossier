using System.Windows;

namespace Strongthium.HostDossier.App;

/// <summary>
/// The command line: a domain or an address looks it up straight away; <c>--sample</c> shows a made-up report, nothing
/// looked up; <c>--theme light|dark</c> sets the look rather than following Windows; <c>--view page</c> opens on that
/// page; <c>--open report.json</c> opens a saved report; <c>--shot file.png</c> saves a picture of the window and quits (for the README's pictures); <c>--wait-for pid</c> is how an update starts the new program.
/// </summary>
internal static class Program
{
    public static string? StartTarget { get; private set; }
    public static bool Sample { get; private set; }
    public static string? StartView { get; private set; }
    public static string? ShotFile { get; private set; }
    public static string? OpenFile { get; private set; }

    public static string SettingsFile { get; } = Path.Combine(Settings.DefaultDirectory, "settings.json");

    [STAThread]
    private static int Main(string[] args)
    {
        string? theme = null;
        int? waitFor = null;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--sample": Sample = true; break;
                case "--theme" when i + 1 < args.Length: theme = args[++i]; break;
                case "--view" when i + 1 < args.Length: StartView = args[++i]; break;
                case "--shot" when i + 1 < args.Length: ShotFile = Path.GetFullPath(args[++i]); break;
                case "--open" when i + 1 < args.Length: OpenFile = Path.GetFullPath(args[++i]); break;
                case "--wait-for" when i + 1 < args.Length && int.TryParse(args[i + 1], out var pid):
                    waitFor = pid;
                    i++;
                    break;
                default:
                    if (!args[i].StartsWith('-')) StartTarget = args[i];
                    break;
            }
        }

        // Updated: the copy that started this one is quitting, and its file can go once it has.
        Updater.Tidy(waitFor);

        var app = new App();
        app.InitializeComponent();
        app.ThemeMode = theme switch
        {
            "light" => ThemeMode.Light,
            "dark" => ThemeMode.Dark,
            _ => ThemeMode.System,
        };
        return app.Run();
    }
}
