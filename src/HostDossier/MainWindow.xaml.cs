using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;

namespace Strongthium.HostDossier.App;

/// <summary>
/// The search box, the report's pages down the side and the page shown. While a lookup runs the page is redrawn when
/// what's on it has changed, twice a second at most, and the scroll position is kept.
/// </summary>
public partial class MainWindow : Window
{
    private readonly Settings settings = Secrets.LoadSettings(Program.SettingsFile);
    private readonly Stack<Dossier> history = new();
    private readonly DispatcherTimer refresh = new() { Interval = TimeSpan.FromMilliseconds(500) };
    private readonly HashSet<string> openRaw = [];
    private Dossier? dossier;
    private CancellationTokenSource? running;
    private List<ReportPage> pages = [];
    private string currentKey = "overview";
    private string? shownFingerprint;
    private int shownRevision = -1;
    private bool loadingNav;
    private SettingsPage? settingsPage;

    public MainWindow()
    {
        InitializeComponent();
        var image = new BitmapImage(new Uri("pack://application:,,,/Assets/host-dossier.png"));
        Logo.Source = image;
        Icon = image;
        refresh.Tick += (_, _) => Refresh();
        Loaded += OnLoaded;
        Closed += (_, _) => running?.Cancel();
        ShowWelcome();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (Program.Sample)
        {
            Query.Text = "example.com";
            ShowDossier(SampleData.Build());
            if (Program.StartView is { } view) currentKey = view;
            if (Program.StartView == "settings") SettingsNav.IsChecked = true;
            Refresh(force: true);
        }
        else if (Program.StartTarget is { } target)
        {
            Query.Text = target;
            await StartAsync(target, remember: false);
        }
        Query.Focus();

        if (Program.ShotFile is { } file)
        {
            // Everything has to be laid out and drawn once, images included, before it can be pictured.
            await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            await Task.Delay(600);
            SavePicture(file);
            Close();
        }
    }

    private void SavePicture(string file)
    {
        var source = PresentationSource.FromVisual(this);
        var scale = source?.CompositionTarget?.TransformToDevice.M11 ?? 1;
        var size = new Size(Root.ActualWidth, Root.ActualHeight);
        var bitmap = new RenderTargetBitmap((int)(size.Width * scale), (int)(size.Height * scale), 96 * scale, 96 * scale, PixelFormats.Pbgra32);
        var visual = new DrawingVisual();
        using (var context = visual.RenderOpen())
        {
            var background = (Brush?)TryFindResource("SolidBackgroundFillColorBaseBrush") ?? Brushes.White;
            context.DrawRectangle(background, null, new Rect(size));
            context.DrawRectangle(new VisualBrush(Root), null, new Rect(size));
        }
        bitmap.Render(visual);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        using var stream = File.Create(file);
        encoder.Save(stream);
    }

    // ---- Looking up ----------------------------------------------------------------------------------------------------

    private void Query_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) _ = StartAsync(Query.Text, remember: true);
    }

    private void Go_Click(object sender, RoutedEventArgs e)
    {
        if (running is not null) running.Cancel();
        else _ = StartAsync(Query.Text, remember: true);
    }

    /// <summary>Looks up a name found in a report: the report stays reachable with Back.</summary>
    public void LookUp(string target)
    {
        Query.Text = target;
        _ = StartAsync(target, remember: true);
    }

    private async Task StartAsync(string text, bool remember)
    {
        if (running is not null) return;
        var target = Names.ParseTarget(text, out var problem);
        if (target is null)
        {
            Status.Text = problem;
            return;
        }
        if (remember && dossier is not null) history.Push(dossier);
        BackButton.IsEnabled = history.Count > 0;

        Query.Text = target.Name;
        var next = Lookup.Begin(target);
        running = new CancellationTokenSource();
        GoButton.Content = "Stop";
        Busy.Visibility = Visibility.Visible;
        currentKey = "overview";
        ShowDossier(next);
        refresh.Start();
        try
        {
            // Off the window's thread: a lookup does some reading and parsing in between its waits.
            using var lookup = new Lookup(settings);
            await Task.Run(() => lookup.RunAsync(next, running.Token));
        }
        catch (OperationCanceledException)
        {
            // Stopped: what was found so far stays on the screen.
        }
        finally
        {
            running.Dispose();
            running = null;
            refresh.Stop();
            GoButton.Content = "Look up";
            Busy.Visibility = Visibility.Collapsed;
            Refresh(force: true);
        }
    }

    private void ShowDossier(Dossier shown)
    {
        dossier = shown;
        shownRevision = -1;
        shownFingerprint = null;
        ExportButton.IsEnabled = true;
        settingsPage = null;
        SettingsNav.IsChecked = false;
        Refresh(force: true);
    }

    private void Back_Click(object sender, RoutedEventArgs e)
    {
        if (history.Count == 0 || running is not null) return;
        var previous = history.Pop();
        BackButton.IsEnabled = history.Count > 0;
        Query.Text = previous.Target.Name;
        currentKey = "overview";
        ShowDossier(previous);
    }

    // ---- The report on the screen ----------------------------------------------------------------------------------------

    private void Refresh(bool force = false)
    {
        if (dossier is null) return;
        var revision = dossier.Revision;
        if (!force && revision == shownRevision) return;
        shownRevision = revision;
        pages = ReportBuilder.Build(dossier);
        UpdateNav();
        UpdateStatus();
        if (SettingsNav.IsChecked != true) ShowCurrentPage(force);
    }

    private void UpdateNav()
    {
        loadingNav = true;
        for (var i = 0; i < pages.Count; i++)
        {
            var page = pages[i];
            RadioButton item;
            if (i < Nav.Children.Count && Nav.Children[i] is RadioButton existing)
            {
                item = existing;
            }
            else
            {
                item = new RadioButton { Style = (Style)FindResource("NavItem"), GroupName = "Pages" };
                item.Checked += Nav_Checked;
                Nav.Children.Insert(i, item);
            }
            item.Name = "";
            item.Uid = page.Key;
            item.Tag = page.Icon;
            item.Content = NavLabel(page);
            item.IsChecked = SettingsNav.IsChecked != true && page.Key == currentKey;
        }
        while (Nav.Children.Count > pages.Count) Nav.Children.RemoveAt(Nav.Children.Count - 1);
        loadingNav = false;
    }

    private static UIElement NavLabel(ReportPage page)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.Children.Add(new TextBlock { Text = page.Title, VerticalAlignment = VerticalAlignment.Center });
        var right = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        if (page.Badge is { } badge)
        {
            right.Children.Add(new TextBlock { Text = badge, FontSize = 12, FontWeight = FontWeights.Normal, Style = (Style)Application.Current.FindResource("Muted"), VerticalAlignment = VerticalAlignment.Center });
        }
        if (page.Worst is { } worst && worst >= Level.Warning)
        {
            var dot = ReportView.Dot(worst);
            dot.Margin = new Thickness(7, 0, 0, 0);
            right.Children.Add(dot);
        }
        Grid.SetColumn(right, 1);
        grid.Children.Add(right);
        return grid;
    }

    private void UpdateStatus()
    {
        if (dossier is null) return;
        var steps = dossier.Read(() => dossier.Steps.ToList());
        var active = steps.Where(s => s.State == "running").Select(s => s.Name).ToList();
        if (dossier.Finished is { } finished)
        {
            var seconds = (finished - dossier.Started).TotalSeconds;
            var failed = steps.Count(s => s.State == "failed");
            Status.Text = $"Finished in {seconds:0} seconds.{(failed > 0 ? $" {failed} steps failed: see Steps." : "")}";
        }
        else if (active.Count > 0)
        {
            Status.Text = "Looking at: " + string.Join(", ", active);
        }
        else
        {
            Status.Text = "Looking…";
        }
    }

    private void ShowCurrentPage(bool force)
    {
        var page = pages.Find(p => p.Key == currentKey) ?? pages.FirstOrDefault();
        if (page is null) return;
        currentKey = page.Key;
        var fingerprint = Fingerprint(page);
        if (!force && fingerprint == shownFingerprint) return;
        shownFingerprint = fingerprint;
        var offset = Scroller.VerticalOffset;
        Page.Content = ReportView.Render(page, this, openRaw);
        Scroller.UpdateLayout();
        Scroller.ScrollToVerticalOffset(offset);
    }

    /// <summary>What's on a page, as text, to tell whether it needs drawing again.</summary>
    private static string Fingerprint(ReportPage page)
    {
        var text = new StringBuilder(page.Key);
        foreach (var block in page.Blocks)
        {
            switch (block)
            {
                case HeadingBlock heading: text.Append(heading.Text).Append(heading.Caption); break;
                case NoteBlock note: text.Append(note.Text); break;
                case RawBlock raw: text.Append(raw.Title).Append(raw.Text.Length); break;
                case FindingsBlock findings:
                    foreach (var finding in findings.Findings) text.Append(finding.Level).Append(finding.Text);
                    break;
                case FactsBlock facts:
                    foreach (var (label, value) in facts.Facts) text.Append(label).Append(value.Text).Append(value.Level);
                    break;
                case TableBlock table:
                    foreach (var row in table.Rows)
                    {
                        foreach (var cell in row) text.Append(cell.Text).Append('|').Append(cell.Level);
                    }
                    break;
            }
        }
        return text.ToString();
    }

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (loadingNav || sender is not RadioButton { Uid: { Length: > 0 } key }) return;
        SettingsNav.IsChecked = false;
        currentKey = key;
        shownFingerprint = null;
        Scroller.ScrollToTop();
        ShowCurrentPage(force: true);
    }

    private void Settings_Checked(object sender, RoutedEventArgs e)
    {
        foreach (var child in Nav.Children.OfType<RadioButton>()) child.IsChecked = false;
        settingsPage ??= new SettingsPage(settings, Program.SettingsFile);
        Page.Content = settingsPage;
        Scroller.ScrollToTop();
    }

    private void ShowWelcome()
    {
        var panel = new StackPanel { MaxWidth = 720, HorizontalAlignment = HorizontalAlignment.Left };
        panel.Children.Add(new TextBlock { Text = "What's behind a domain or an address?", Style = (Style)FindResource("PageTitle"), Margin = new Thickness(0, 12, 0, 12) });
        panel.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            FontSize = 14,
            Text = "Enter a domain or an IP address above. host-dossier finds out who registered it and who holds its network, every DNS record, " +
                "where each address really is, how its TLS is set up, which ports answer and what's listening, how its mail is set up, down to every address " +
                "its SPF record allows, and whether those are on blocklists. Then it follows the other domains it finds along the way.",
        });
        panel.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 12, 0, 0),
            Style = (Style)FindResource("Caption"),
            Text = "A lookup connects to the server being looked up, including a scan of common ports. Only scan servers you have permission to scan: what to do is in Settings.",
        });
        Page.Content = panel;
    }

    // ---- Saving -----------------------------------------------------------------------------------------------------------

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (dossier is null) return;
        var hasOrigins = dossier.Read(() => dossier.Cloudflare.Zones.Count > 0);
        if (hasOrigins && MessageBox.Show(this, "This report holds your Cloudflare records, with the real addresses behind Cloudflare. Save it anyway?",
                "Save report", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }
        var dialog = new SaveFileDialog
        {
            FileName = $"{dossier.Target.Name.Replace(':', '-')}-{DateTime.Now:yyyy-MM-dd}",
            Filter = "Markdown report (*.md)|*.md|Everything, as JSON (*.json)|*.json",
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            File.WriteAllText(dialog.FileName, Path.GetExtension(dialog.FileName).Equals(".json", StringComparison.OrdinalIgnoreCase) ? Export.ToJson(dossier) : Export.ToMarkdown(dossier));
            Status.Text = $"Saved to {dialog.FileName}.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, exception.Message, "Save report", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
