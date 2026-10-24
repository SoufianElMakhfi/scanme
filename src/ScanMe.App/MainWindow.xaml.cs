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

    /// <summary>Gesetzt beim Rendern fuer Screenshots: keine Dialoge, keine Netzwerkzugriffe.</summary>
    public bool Headless { get; set; }

    private const string DisclaimerVersion = "1";

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (Headless) return;
        if (!ConfirmDisclaimer())
        {
            ExitApplication();
            return;
        }
        _tray = new TrayIcon(this, _vm);
        if (_vm.Settings.StartMonitorOnLaunch && !_vm.Monitor.IsRunning) _vm.Monitor.Toggle();
        await _vm.CheckOnlineAsync();
    }

    private bool ConfirmDisclaimer()
    {
        if (_vm.Settings.DisclaimerAccepted == DisclaimerVersion) return true;
        var result = MessageBox.Show(
            "ScanMe ist kostenlose Open-Source-Software (GPL-3.0) und wird OHNE JEDE GEWÄHRLEISTUNG bereitgestellt.\n\n" +
            "• ScanMe arbeitet mit Heuristiken: Es kann Schadsoftware übersehen und harmlose Programme als verdächtig melden.\n" +
            "• ScanMe ersetzt keinen Virenscanner und keine professionelle IT-Forensik.\n" +
            "• Sie entscheiden selbst über jede Aktion (Beenden, Quarantäne, Deaktivieren). Prüfen Sie Funde, bevor Sie handeln, " +
            "und sichern Sie wichtige Daten.\n" +
            "• Die Nutzung erfolgt auf eigene Verantwortung. Die Autoren haften nicht für Schäden, soweit gesetzlich zulässig.\n\n" +
            "Online-Funktionen (abschaltbar in den Einstellungen): ScanMe fragt bei GitHub nach Updates und signierten Erkennungsregeln. " +
            "Dabei werden keine Daten von Ihrem PC übertragen.\n\n" +
            "Akzeptieren Sie diese Bedingungen?",
            "ScanMe – Nutzungshinweis", MessageBoxButton.YesNo, MessageBoxImage.Information);
        if (result != MessageBoxResult.Yes) return false;
        _vm.Settings.DisclaimerAccepted = DisclaimerVersion;
        _vm.Settings.Save();
        return true;
    }

    private void OnViewModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(MainViewModel.CurrentPage)) return;
        var nav = _vm.CurrentPage switch
        {
            FindingsViewModel => NavFindings,
            ProcessesViewModel => NavProcesses,
            MonitorViewModel => NavMonitor,
            HardeningViewModel => NavHardening,
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
