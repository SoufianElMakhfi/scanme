using System.ComponentModel;
using System.Windows;
using ScanMe.App.ViewModels;

namespace ScanMe.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm = new();
    private TrayIcon? _tray;
    private bool _exiting;
    private bool _trayHintShown;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _vm;
        // Navigationsmarkierung synchron halten, wenn aus dem Code heraus navigiert wird (z. B. Klick auf Fund im Dashboard)
        _vm.PropertyChanged += OnViewModelChanged;
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        _tray = new TrayIcon(this, _vm);
        if (_vm.Settings.StartMonitorOnLaunch && !_vm.Monitor.IsRunning) _vm.Monitor.Toggle();
    }

    private void OnViewModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(MainViewModel.CurrentPage)) return;
        var nav = _vm.CurrentPage switch
        {
            FindingsViewModel => NavFindings,
            ProcessesViewModel => NavProcesses,
            MonitorViewModel => NavMonitor,
            QuarantineViewModel => NavQuarantine,
            SettingsViewModel => NavSettings,
            _ => NavDashboard,
        };
        nav.IsChecked = true;
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // Laeuft die Ueberwachung, bleibt ScanMe im Infobereich aktiv.
        if (!_exiting && _vm.Monitor.IsRunning && _vm.Settings.MinimizeToTray && _tray != null)
        {
            e.Cancel = true;
            Hide();
            if (!_trayHintShown)
            {
                _tray.ShowHint("ScanMe läuft weiter", "Die Echtzeitüberwachung ist aktiv. Über das Symbol im Infobereich öffnen oder beenden.");
                _trayHintShown = true;
            }
            return;
        }
        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        _vm.Monitor.Shutdown();
        _tray?.Dispose();
        base.OnClosed(e);
    }

    public void ExitApplication()
    {
        _exiting = true;
        Close();
    }
}
