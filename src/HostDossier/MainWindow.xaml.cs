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
    private readonly Stack<(Dossier Report, string? Note)> history = new();
    private readonly ReportCache cache = new(ReportCache.DefaultDirectory);
    /// <summary>Where the report on the screen came from, when it isn't a lookup just made.</summary>
    private string? sourceNote;
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
            if (Program.StartView == "history") HistoryNav.IsChecked = true;
            Refresh(force: true);
        }
        else if (Program.OpenFile is { } report)
        {
            OpenReportFile(report);
            if (Program.StartView is { } view)
            {
                currentKey = view;
                Refresh(force: true);
            }
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

    private void Again_Click(object sender, RoutedEventArgs e)
    {
        if (dossier is not null) _ = StartAsync(dossier.Target.Name, remember: false, fresh: true);
    }

    /// <summary>Looks up a name found in a report: the report stays reachable with Back.</summary>
    public void LookUp(string target)
    {
        Query.Text = target;
        _ = StartAsync(target, remember: true);
    }

    /// <summary>Shows what's kept for the target when it's recent enough, and looks it up otherwise. Asking again for what's
    /// on the screen means looking it up, or nothing could ever bring it up to date.</summary>
    private async Task StartAsync(string text, bool remember, bool fresh = false)
    {
        if (running is not null) return;
        var target = Names.ParseTarget(text, out var problem);
        if (target is null)
        {
            Status.Text = problem;
            return;
        }
        var same = dossier?.Target.Name == target.Name;
        if (remember && dossier is not null && !same) history.Push((dossier, sourceNote));
        BackButton.IsEnabled = history.Count > 0;
        Query.Text = target.Name;
        currentKey = "overview";

        if (!fresh && !same && settings.KeepReports && settings.CacheHours > 0 && cache.Find(target.Name, TimeSpan.FromHours(settings.CacheHours)) is not null && cache.Load(target.Name) is { } cached)
        {
            ShowDossier(cached, "From the cache");
            return;
        }

        var next = Lookup.Begin(target);
        running = new CancellationTokenSource();
        GoButton.Content = "Stop";
        Busy.Visibility = Visibility.Visible;
        ShowDossier(next);
        refresh.Start();
        var stopped = false;
        try
        {
            // Off the window's thread: a lookup does some reading and parsing in between its waits.
            using var lookup = new Lookup(settings);
            await Task.Run(() => lookup.RunAsync(next, running.Token));
            stopped = running.IsCancellationRequested;
        }
        catch (OperationCanceledException)
        {
            // Stopped: what was found so far stays on the screen.
            stopped = true;
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
        // Half a report isn't kept: next time it would pass for the whole of it.
        if (!stopped && settings.KeepReports) await KeepAsync(next);
    }

    private async Task KeepAsync(Dossier finished)
    {
        try
        {
            await Task.Run(() => cache.Save(finished));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Status.Text += $" It couldn't be kept: {exception.Message}";
        }
    }

    private void ShowDossier(Dossier shown, string? note = null)
    {
        dossier = shown;
        sourceNote = note;
        shownRevision = -1;
        shownFingerprint = null;
        ExportButton.IsEnabled = true;
        settingsPage = null;
        SettingsNav.IsChecked = false;
        HistoryNav.IsChecked = false;
        Refresh(force: true);
    }

    private void Back_Click(object sender, RoutedEventArgs e)
    {
        if (history.Count == 0 || running is not null) return;
        var (previous, note) = history.Pop();
        BackButton.IsEnabled = history.Count > 0;
        Query.Text = previous.Target.Name;
        currentKey = "overview";
        ShowDossier(previous, note);
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
        if (ShowingReport) ShowCurrentPage(force);
    }

    private bool ShowingReport => SettingsNav.IsChecked != true && HistoryNav.IsChecked != true;

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
            item.IsChecked = ShowingReport && page.Key == currentKey;
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
        AgainButton.Visibility = sourceNote is null ? Visibility.Collapsed : Visibility.Visible;
        if (sourceNote is not null)
        {
            Status.Text = $"{sourceNote}: looked up {Age(dossier.Finished ?? dossier.Started)}.";
            return;
        }
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
        HistoryNav.IsChecked = false;
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

    private void History_Checked(object sender, RoutedEventArgs e)
    {
        foreach (var child in Nav.Children.OfType<RadioButton>()) child.IsChecked = false;
        ShowHistory();
    }

    private void ShowHistory()
    {
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock { Text = "History", Style = (Style)FindResource("PageTitle"), Margin = new Thickness(0, 0, 0, 4) });
        panel.Children.Add(new TextBlock { Text = "The last report of everything looked up. Click one to open it as it was, with nothing looked up again.", Style = (Style)FindResource("Caption"), Margin = new Thickness(0, 0, 0, 12) });
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
        var open = new Button { Content = "Open a saved report…", Padding = new Thickness(12, 5, 12, 5) };
        open.Click += Open_Click;
        buttons.Children.Add(open);
        var reports = cache.List();
        if (reports.Count > 0)
        {
            var clear = new Button { Content = "Clear the history", Padding = new Thickness(12, 5, 12, 5), Margin = new Thickness(8, 0, 0, 0) };
            clear.Click += (_, _) =>
            {
                if (MessageBox.Show(this, $"Delete the {reports.Count} kept reports?", "History", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
                cache.Clear();
                ShowHistory();
            };
            buttons.Children.Add(clear);
        }
        panel.Children.Add(buttons);
        panel.Children.Add(reports.Count == 0
            ? new TextBlock { Text = "Nothing yet: reports are kept here as lookups finish.", Style = (Style)FindResource("Muted") }
            : new Border { Style = (Style)FindResource("Card"), Child = ReportList(reports, withRemove: true) });
        Page.Content = panel;
        Scroller.ScrollToTop();
    }

    private Grid ReportList(IReadOnlyList<CachedReport> reports, bool withRemove)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        for (var i = 0; i < reports.Count; i++)
        {
            var report = reports[i];
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var link = new System.Windows.Documents.Hyperlink(new System.Windows.Documents.Run(report.Target));
            link.Click += (_, _) => OpenKept(report.Target);
            var name = new TextBlock { Margin = new Thickness(0, 4, 24, 4), VerticalAlignment = VerticalAlignment.Center };
            name.Inlines.Add(link);
            Grid.SetRow(name, i);
            grid.Children.Add(name);
            var when = new TextBlock { Text = Age(report.LookedUp), Style = (Style)FindResource("Muted"), VerticalAlignment = VerticalAlignment.Center };
            Grid.SetRow(when, i);
            Grid.SetColumn(when, 1);
            grid.Children.Add(when);
            if (!withRemove) continue;
            var remove = new Button { Content = "Remove", Padding = new Thickness(8, 2, 8, 2), FontSize = 12, Margin = new Thickness(0, 2, 0, 2) };
            remove.Click += (_, _) =>
            {
                cache.Remove(report.Target);
                ShowHistory();
            };
            Grid.SetRow(remove, i);
            Grid.SetColumn(remove, 2);
            grid.Children.Add(remove);
        }
        return grid;
    }

    private void OpenKept(string target)
    {
        if (running is not null) return;
        if (cache.Load(target) is not { } report)
        {
            Status.Text = $"The report of {target} can't be read.";
            return;
        }
        ShowOpened(report, "From the history");
    }

    private void ShowOpened(Dossier report, string note)
    {
        if (dossier is not null) history.Push((dossier, sourceNote));
        BackButton.IsEnabled = history.Count > 0;
        Query.Text = report.Target.Name;
        currentKey = "overview";
        ShowDossier(report, note);
        Scroller.ScrollToTop();
    }

    private void Open_Click(object sender, RoutedEventArgs e)
    {
        if (running is not null) return;
        var dialog = new OpenFileDialog { Filter = "Saved reports (*.json)|*.json|All files (*.*)|*.*" };
        if (dialog.ShowDialog(this) == true) OpenReportFile(dialog.FileName);
    }

    private void OpenReportFile(string file)
    {
        try
        {
            ShowOpened(Export.FromJson(File.ReadAllText(file)), $"Opened from {Path.GetFileName(file)}");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            MessageBox.Show(this, exception.Message, "Open a report", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static string Age(DateTimeOffset when)
    {
        var age = DateTimeOffset.UtcNow - when;
        var text = age.TotalMinutes < 1 ? "just now"
            : age.TotalHours < 1 ? $"{(int)age.TotalMinutes} minutes ago"
            : age.TotalDays < 1 ? $"{(int)age.TotalHours} hours ago"
            : $"{(int)age.TotalDays} days ago";
        return $"{text} ({when.ToLocalTime():yyyy-MM-dd HH:mm})";
    }

    /// <summary>
    /// The wheel scrolls the page wherever the mouse is. Each table has a scroller of its own for its width, which would
    /// otherwise take the wheel and do nothing with it. Only something that can really move that way keeps it, such as a
    /// long WHOIS answer; Shift and the wheel move a wide table sideways.
    /// </summary>
    private void Scroller_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        for (var over = e.OriginalSource as DependencyObject; over is not null && !ReferenceEquals(over, Scroller); over = over is Visual or System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(over) : LogicalTreeHelper.GetParent(over))
        {
            if (over is not ScrollViewer inner) continue;
            if (Keyboard.Modifiers.HasFlag(ModifierKeys.Shift) && inner.ScrollableWidth > 0)
            {
                inner.ScrollToHorizontalOffset(inner.HorizontalOffset - e.Delta * WheelStep);
                e.Handled = true;
                return;
            }
            if (e.Delta < 0 ? inner.VerticalOffset < inner.ScrollableHeight : inner.VerticalOffset > 0) return;
        }
        Scroller.ScrollToVerticalOffset(Scroller.VerticalOffset - e.Delta * WheelStep);
        e.Handled = true;
    }

    /// <summary>What Windows' scrollers move for a notch of the wheel: 48 pixels for its 120.</summary>
    private const double WheelStep = 0.4;

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
        var recent = cache.List().Take(8).ToList();
        if (recent.Count > 0)
        {
            panel.Children.Add(new TextBlock { Text = "Looked up before", Style = (Style)FindResource("Heading"), Margin = new Thickness(0, 22, 0, 8) });
            panel.Children.Add(new Border { Style = (Style)FindResource("Card"), Child = ReportList(recent, withRemove: false) });
        }
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
            Filter = "Report that can be opened again (*.json)|*.json|Markdown, to read or share (*.md)|*.md",
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
