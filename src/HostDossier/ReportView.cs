using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace Strongthium.HostDossier.App;

/// <summary>Draws a report page's blocks. A page is drawn afresh when what's on it changes, so nothing here keeps state
/// but which raw texts were left open.</summary>
internal static class ReportView
{
    private const int RowsAtFirst = 200;
    private static readonly FontFamily Mono = new("Cascadia Mono, Consolas");
    private static readonly Dictionary<string, BitmapImage?> Flags = new(StringComparer.Ordinal);

    public static FrameworkElement Render(ReportPage page, MainWindow window, HashSet<string> openRaw)
    {
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock { Text = page.Title, Style = Style("PageTitle"), Margin = new Thickness(0, 0, 0, 10) });
        foreach (var block in page.Blocks)
        {
            panel.Children.Add(block switch
            {
                HeadingBlock heading => Heading(heading),
                NoteBlock note => new TextBlock { Text = note.Text, Style = Style("Muted"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 10) },
                FindingsBlock findings => Findings(findings),
                FactsBlock facts => Facts(facts, window),
                TableBlock table => Table(table, window),
                RawBlock raw => Raw(raw, openRaw),
                _ => new Border(),
            });
        }
        return panel;
    }

    private static Style Style(string key) => (Style)Application.Current.FindResource(key);

    private static Border Card(UIElement child) => new() { Style = Style("Card"), Child = child, Margin = new Thickness(0, 0, 0, 12) };

    private static UIElement Heading(HeadingBlock heading)
    {
        var panel = new StackPanel { Margin = new Thickness(0, 12, 0, 8) };
        panel.Children.Add(new TextBlock { Text = heading.Text, Style = Style("Heading") });
        if (heading.Caption is { } caption) panel.Children.Add(new TextBlock { Text = caption, Style = Style("Caption"), Margin = new Thickness(0, 2, 0, 0) });
        return panel;
    }

    /// <summary>The theme's status colours, the same ones Windows uses for its own good and bad news.</summary>
    private static string BrushKey(Level level) => level switch
    {
        Level.Good => "SystemFillColorSuccessBrush",
        Level.Info => "SystemFillColorNeutralBrush",
        Level.Notice => "SystemFillColorCautionBrush",
        Level.Warning => "SystemFillColorCautionBrush",
        _ => "SystemFillColorCriticalBrush",
    };

    private static string Glyph(Level level) => level switch
    {
        Level.Good => "",
        Level.Info => "",
        Level.Notice => "",
        Level.Warning => "",
        _ => "",
    };

    public static FrameworkElement Dot(Level level)
    {
        var dot = new Ellipse { Width = 8, Height = 8, VerticalAlignment = VerticalAlignment.Center };
        dot.SetResourceReference(Shape.FillProperty, BrushKey(level));
        return dot;
    }

    private static UIElement Findings(FindingsBlock block)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(26) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        for (var i = 0; i < block.Findings.Count; i++)
        {
            var finding = block.Findings[i];
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var icon = new TextBlock { Text = Glyph(finding.Level), Style = Style("Icon"), FontSize = 14, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 3, 0, 0) };
            icon.SetResourceReference(TextBlock.ForegroundProperty, BrushKey(finding.Level));
            Grid.SetRow(icon, i);
            grid.Children.Add(icon);
            var text = new TextBlock { Text = finding.Text, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 4), ToolTip = finding.Area };
            AddCopy(text, finding.Text);
            Grid.SetRow(text, i);
            Grid.SetColumn(text, 1);
            grid.Children.Add(text);
        }
        return Card(grid);
    }

    private static UIElement Facts(FactsBlock block, MainWindow window)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto, MaxWidth = 280 });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        for (var i = 0; i < block.Facts.Count; i++)
        {
            var (label, value) = block.Facts[i];
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var name = new TextBlock { Text = label, Style = Style("Muted"), Margin = new Thickness(0, 3, 22, 3), TextWrapping = TextWrapping.Wrap, MaxWidth = 250 };
            Grid.SetRow(name, i);
            grid.Children.Add(name);
            var content = CellElement(value, window, wrapWidth: double.PositiveInfinity);
            content.Margin = new Thickness(0, 3, 0, 3);
            Grid.SetRow(content, i);
            Grid.SetColumn(content, 1);
            grid.Children.Add(content);
        }
        return Card(grid);
    }

    private static UIElement Table(TableBlock table, MainWindow window)
    {
        if (table.Rows.Count == 0)
        {
            return table.Empty is { } empty ? new TextBlock { Text = empty, Style = Style("Muted"), Margin = new Thickness(0, 2, 0, 12) } : new Border();
        }
        var holder = new Border();
        void Draw(int limit)
        {
            // Room at the bottom for the scroll bar, which is drawn over what's under it.
            var grid = new Grid { Margin = new Thickness(0, 0, 0, 8) };
            foreach (var _ in table.Columns) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            for (var column = 0; column < table.Columns.Count; column++)
            {
                var header = new TextBlock { Text = table.Columns[column], FontWeight = FontWeights.SemiBold, FontSize = 12, Margin = new Thickness(0, 0, 18, 6) };
                header.SetResourceReference(TextBlock.ForegroundProperty, "TextFillColorSecondaryBrush");
                Grid.SetColumn(header, column);
                grid.Children.Add(header);
            }
            var shown = Math.Min(limit, table.Rows.Count);
            for (var r = 0; r < shown; r++)
            {
                grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                var line = new Border { BorderThickness = new Thickness(0, 1, 0, 0) };
                line.SetResourceReference(Border.BorderBrushProperty, "DividerStrokeColorDefaultBrush");
                Grid.SetRow(line, r + 1);
                Grid.SetColumnSpan(line, Math.Max(1, table.Columns.Count));
                grid.Children.Add(line);
                var row = table.Rows[r];
                for (var c = 0; c < row.Count && c < table.Columns.Count; c++)
                {
                    // The last column usually holds the long text, and the others shouldn't push it out of sight.
                    var element = CellElement(row[c], window, wrapWidth: c < table.Columns.Count - 1 ? 300 : table.Columns.Count >= 7 ? 270 : 560);
                    element.Margin = new Thickness(row[c].Indent * 18, 5, 18, 5);
                    element.VerticalAlignment = VerticalAlignment.Top;
                    Grid.SetRow(element, r + 1);
                    Grid.SetColumn(element, c);
                    grid.Children.Add(element);
                }
            }
            var inner = new StackPanel();
            inner.Children.Add(new ScrollViewer { Content = grid, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled, Focusable = false, PanningMode = PanningMode.HorizontalOnly });
            if (shown < table.Rows.Count)
            {
                var more = new Button { Content = $"Show all {table.Rows.Count:N0} rows", Margin = new Thickness(0, 8, 0, 0), HorizontalAlignment = HorizontalAlignment.Left };
                more.Click += (_, _) => Draw(int.MaxValue);
                inner.Children.Add(more);
            }
            holder.Child = inner;
        }
        Draw(RowsAtFirst);
        AddTableCopy(holder, table);
        return Card(holder);
    }

    private static FrameworkElement CellElement(Cell cell, MainWindow window, double wrapWidth)
    {
        var text = new TextBlock { TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
        if (!double.IsInfinity(wrapWidth)) text.MaxWidth = wrapWidth;
        if (cell.Mono)
        {
            text.FontFamily = Mono;
            text.FontSize = 12.5;
        }
        if (cell.Lookup is { } lookup)
        {
            var link = new Hyperlink(new Run(cell.Text)) { ToolTip = $"Look up {lookup}" };
            link.Click += (_, _) => window.LookUp(lookup);
            text.Inlines.Add(link);
        }
        else if (cell.Url is { } url)
        {
            var link = new Hyperlink(new Run(cell.Text)) { ToolTip = url };
            link.Click += (_, _) => OpenWeb(url);
            text.Inlines.Add(link);
        }
        else
        {
            text.Text = cell.Text;
        }
        AddCopy(text, cell.Text);

        if (cell.Level is not { } level && cell.Country is null) return text;

        var panel = new StackPanel { Orientation = Orientation.Horizontal };
        if (cell.Country is { } country && FlagOf(country) is { } flag)
        {
            panel.Children.Add(new Image { Source = flag, Height = 13, Margin = new Thickness(0, 0, 7, 0), VerticalAlignment = VerticalAlignment.Center, ToolTip = country, SnapsToDevicePixels = true });
        }
        if (cell.Level is { } shown)
        {
            var dot = Dot(shown);
            dot.Margin = new Thickness(0, 0, 7, 0);
            panel.Children.Add(dot);
        }
        panel.Children.Add(text);
        return panel;
    }

    private static BitmapImage? FlagOf(string country)
    {
        var code = country.ToLowerInvariant();
        if (Flags.TryGetValue(code, out var known)) return known;
        BitmapImage? image = null;
        try
        {
            image = new BitmapImage(new Uri($"pack://application:,,,/Assets/flags/{code}.png"));
            image.Freeze();
        }
        catch (IOException)
        {
            // A country code there's no flag for: the name alone says it.
        }
        Flags[code] = image;
        return image;
    }

    private static UIElement Raw(RawBlock raw, HashSet<string> openRaw)
    {
        var box = new TextBox
        {
            Text = raw.Text,
            IsReadOnly = true,
            FontFamily = Mono,
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
            MaxHeight = 420,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        };
        var expander = new Expander { Header = raw.Title, Content = box, Margin = new Thickness(0, 0, 0, 8), IsExpanded = openRaw.Contains(raw.Title), HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch };
        expander.Expanded += (_, _) => openRaw.Add(raw.Title);
        expander.Collapsed += (_, _) => openRaw.Remove(raw.Title);
        return expander;
    }

    private static void AddCopy(TextBlock text, string value)
    {
        if (string.IsNullOrEmpty(value)) return;
        text.MouseRightButtonUp += (_, e) =>
        {
            var menu = new ContextMenu();
            var copy = new MenuItem { Header = "Copy" };
            copy.Click += (_, _) => TrySetClipboard(value);
            menu.Items.Add(copy);
            menu.IsOpen = true;
            e.Handled = true;
        };
    }

    private static void AddTableCopy(Border holder, TableBlock table)
    {
        holder.MouseRightButtonUp += (_, e) =>
        {
            var menu = new ContextMenu();
            var copy = new MenuItem { Header = "Copy the table" };
            copy.Click += (_, _) =>
            {
                var lines = new List<string> { string.Join('\t', table.Columns) };
                lines.AddRange(table.Rows.Select(r => string.Join('\t', r.Select(c => c.Text))));
                TrySetClipboard(string.Join("\r\n", lines));
            };
            menu.Items.Add(copy);
            menu.IsOpen = true;
            e.Handled = true;
        };
    }

    private static void TrySetClipboard(string text)
    {
        try
        {
            Clipboard.SetDataObject(text);
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            // Another program has the clipboard open just now: it's a copy that didn't happen, nothing more.
        }
    }

    private static void OpenWeb(string url)
    {
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase) && !url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return;
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }
}
