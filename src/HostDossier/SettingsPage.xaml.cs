using System.Windows;
using System.Windows.Controls;

namespace Strongthium.HostDossier.App;

public partial class SettingsPage : UserControl
{
    private readonly Settings settings;
    private readonly string file;
    private bool loading;

    public SettingsPage(Settings settings, string file)
    {
        this.settings = settings;
        this.file = file;
        InitializeComponent();
        loading = true;
        DoRegistration.IsChecked = settings.Registration;
        DoDns.IsChecked = settings.Dns;
        DoLogs.IsChecked = settings.CertificateLogs;
        DoTls.IsChecked = settings.Tls;
        DoPorts.IsChecked = settings.Ports;
        DoWeb.IsChecked = settings.Web;
        DoMail.IsChecked = settings.Mail;
        DoBlocklists.IsChecked = settings.Blocklists;
        DoFollow.IsChecked = settings.FollowRelated;
        DoCdnScan.IsChecked = settings.ScanCdnAddresses;
        Depth.Text = settings.FollowDepth.ToString();
        FollowLimit.Text = settings.FollowLimit.ToString();
        TlsAddresses.Text = settings.TlsAddresses.ToString();
        PortAddresses.Text = settings.PortScanAddresses.ToString();
        PerNetwork.Text = settings.AddressesPerNetwork.ToString();
        Budget.Text = settings.MailAddressBudget.ToString();
        PortList.Text = settings.PortList;
        Selectors.Text = string.Join(", ", settings.DkimSelectors);
        Resolvers.Text = string.Join(", ", settings.Resolvers);
        loading = false;

        foreach (var box in new[] { DoRegistration, DoDns, DoLogs, DoTls, DoPorts, DoWeb, DoMail, DoBlocklists, DoFollow, DoCdnScan })
        {
            box.Click += (_, _) => Apply();
        }
        foreach (var box in new[] { Depth, FollowLimit, TlsAddresses, PortAddresses, PerNetwork, Budget, PortList, Selectors, Resolvers })
        {
            box.LostFocus += (_, _) => Apply();
        }
        ShowLists();
        ShowAccounts();
    }

    private void Apply()
    {
        if (loading) return;
        settings.Registration = DoRegistration.IsChecked == true;
        settings.Dns = DoDns.IsChecked == true;
        settings.CertificateLogs = DoLogs.IsChecked == true;
        settings.Tls = DoTls.IsChecked == true;
        settings.Ports = DoPorts.IsChecked == true;
        settings.Web = DoWeb.IsChecked == true;
        settings.Mail = DoMail.IsChecked == true;
        settings.Blocklists = DoBlocklists.IsChecked == true;
        settings.FollowRelated = DoFollow.IsChecked == true;
        settings.ScanCdnAddresses = DoCdnScan.IsChecked == true;
        settings.FollowDepth = Number(Depth, settings.FollowDepth, 0, 5);
        settings.FollowLimit = Number(FollowLimit, settings.FollowLimit, 0, 500);
        settings.TlsAddresses = Number(TlsAddresses, settings.TlsAddresses, 0, 16);
        settings.PortScanAddresses = Number(PortAddresses, settings.PortScanAddresses, 0, 64);
        settings.AddressesPerNetwork = Number(PerNetwork, settings.AddressesPerNetwork, 1, 65536);
        settings.MailAddressBudget = Number(Budget, settings.MailAddressBudget, 0, 100000);
        settings.PortList = PortList.Text.Trim();
        settings.DkimSelectors = Words(Selectors.Text);
        settings.Resolvers = Words(Resolvers.Text).Where(Names.IsAddress).ToList();
        Save();
    }

    private static List<string> Words(string text) =>
        text.Split([',', ' ', '\n', '\r', '\t', ';'], StringSplitOptions.RemoveEmptyEntries).Distinct().ToList();

    private static int Number(TextBox box, int current, int least, int most)
    {
        var value = int.TryParse(box.Text, out var number) ? Math.Clamp(number, least, most) : current;
        box.Text = value.ToString();
        return value;
    }

    private void Save()
    {
        try
        {
            settings.Save(file);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(Window.GetWindow(this), exception.Message, "Settings", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    // ---- Blocklists -----------------------------------------------------------------------------------------------------

    private void ShowLists()
    {
        ListsPanel.Items.Clear();
        foreach (var entry in settings.BlocklistEntries)
        {
            var row = new DockPanel { Margin = new Thickness(0, 1, 0, 1) };
            var remove = new Button { Content = "Remove", Padding = new Thickness(8, 2, 8, 2), FontSize = 12 };
            remove.Click += (_, _) =>
            {
                settings.BlocklistEntries.Remove(entry);
                Save();
                ShowLists();
            };
            DockPanel.SetDock(remove, Dock.Right);
            row.Children.Add(remove);
            var box = new CheckBox { IsChecked = entry.Enabled, Content = $"{entry.Name}  ({entry.Zone})", ToolTip = entry.Note };
            box.Click += (_, _) =>
            {
                entry.Enabled = box.IsChecked == true;
                Save();
            };
            row.Children.Add(box);
            ListsPanel.Items.Add(row);
        }
    }

    private void AddList_Click(object sender, RoutedEventArgs e)
    {
        var zone = Names.NormalizeName(NewZone.Text);
        if (zone is null || settings.BlocklistEntries.Exists(l => l.Zone == zone)) return;
        settings.BlocklistEntries.Add(new BlocklistEntry { Zone = zone, Name = NewZoneName.Text.Trim() is { Length: > 0 } name ? name : zone });
        NewZone.Clear();
        NewZoneName.Clear();
        Save();
        ShowLists();
    }

    // ---- Cloudflare ------------------------------------------------------------------------------------------------------

    private void ShowAccounts()
    {
        CloudflareList.Items.Clear();
        foreach (var account in settings.CloudflareAccounts)
        {
            var row = new DockPanel { Margin = new Thickness(0, 1, 0, 3) };
            var remove = new Button { Content = "Remove", Padding = new Thickness(8, 2, 8, 2), FontSize = 12 };
            remove.Click += (_, _) =>
            {
                settings.CloudflareAccounts.Remove(account);
                Save();
                ShowAccounts();
            };
            DockPanel.SetDock(remove, Dock.Right);
            row.Children.Add(remove);
            row.Children.Add(new TextBlock { Text = account.Token is null ? $"{account.Name}: can't be read on this PC, enter it again" : account.Name, VerticalAlignment = VerticalAlignment.Center });
            CloudflareList.Items.Add(row);
        }
    }

    private async void AddToken_Click(object sender, RoutedEventArgs e)
    {
        var token = TokenValue.Password.Trim();
        if (token.Length == 0) return;
        TokenStatus.Text = "Asking Cloudflare…";
        try
        {
            using var http = new HttpClient();
            var zones = await new CloudflareClient(http, token).ListZonesAsync(CancellationToken.None);
            settings.CloudflareAccounts.Add(new CloudflareAccount { Name = TokenName.Text.Trim() is { Length: > 0 } name ? name : "Cloudflare", Protected = Secrets.Protect(token), Token = token });
            Save();
            TokenValue.Clear();
            ShowAccounts();
            TokenStatus.Text = zones.Count == 0
                ? "Added, but this token can't see any zones: it needs Zone Read."
                : $"Added. It can see {zones.Count} zones: {string.Join(", ", zones.Take(8))}{(zones.Count > 8 ? " and more" : "")}.";
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            TokenStatus.Text = "Not added: " + exception.Message;
        }
    }
}
