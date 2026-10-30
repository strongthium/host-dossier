using System.Windows;
using System.Windows.Threading;

namespace Strongthium.HostDossier.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandled;
        new MainWindow().Show();
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // Something the program didn't expect is shown, rather than the program disappearing with the report in it.
        MessageBox.Show(e.Exception.Message, "host-dossier", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }
}
