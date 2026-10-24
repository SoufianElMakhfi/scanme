using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ScanMe.Core.Actions;
using ScanMe.Core.Engine;
using ScanMe.Core.Models;
using ScanMe.Core.Scanners;
using ScanMe.Core.Updates;
using ScanMe.Core.Util;

namespace ScanMe.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    private CancellationTokenSource? _cts;

    public MainViewModel()
    {
        Settings = AppSettings.Load();
        Dashboard = new DashboardViewModel(this);
        Findings = new FindingsViewModel(this);
        Timeline = new TimelineViewModel(this);
        Processes = new ProcessesViewModel();
        Quarantine = new QuarantineViewModel();
        SettingsPage = new SettingsViewModel(this);
        Monitor = new MonitorViewModel(this);
        Hardening = new HardeningViewModel();
        _currentPage = Dashboard;
    }

    public MonitorViewModel Monitor { get; }
    public HardeningViewModel Hardening { get; }

    public AppSettings Settings { get; }
    public DashboardViewModel Dashboard { get; }
    public FindingsViewModel Findings { get; }
    public TimelineViewModel Timeline { get; }
    public ProcessesViewModel Processes { get; }
    public QuarantineViewModel Quarantine { get; }
    public SettingsViewModel SettingsPage { get; }

    public bool IsElevated { get; } = SystemEnv.IsElevated;
    public string OsDescription { get; } = SystemEnv.OsDescription;
    public string MachineName { get; } = Environment.MachineName;

    [ObservableProperty] private object _currentPage;
    [ObservableProperty] private ScanReport? _lastReport;
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(StartQuickScanCommand), nameof(StartFullScanCommand))] private bool _isScanning;
    [ObservableProperty] private double _scanPercent;
    [ObservableProperty] private string _scanStatus = "Bereit.";
    [ObservableProperty] private string _scanStep = "";
    [ObservableProperty] private UpdateInfo? _availableUpdate;
    [ObservableProperty] private string _rulesStatus = RuleStore.Version > 0 ? $"Online-Regeln: Version {RuleStore.Version}" : "Nur eingebaute Regeln";

    public string AppVersion { get; } = "Version " + OnlineUpdates.CurrentVersion.ToString(3);
    public string CurrentVersionText { get; } = OnlineUpdates.CurrentVersion.ToString(3);

    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(InstallUpdateCommand))] private bool _isUpdating;
    [ObservableProperty] private string? _updateStatus;

    /// <summary>Warnung aus dem signierten Regelpaket, falls diese Version einen bekannten schweren Fehler hat.</summary>
    [ObservableProperty] private string? _appWarning = RuleStore.AppWarning;

    /// <summary>Beim Start: nach neuer Version fragen und Regeln aktualisieren (nur wenn erlaubt).</summary>
    public async Task CheckOnlineAsync()
    {
        if (!Settings.OnlineFeatures) return;
        AvailableUpdate = await OnlineUpdates.CheckForUpdateAsync();
        RulesStatus = await OnlineUpdates.UpdateRulesAsync();
        AppWarning = RuleStore.AppWarning;
    }

    private bool CanInstallUpdate() => !IsUpdating;

    /// <summary>Ein-Klick-Update: laden, pruefen (Pruefsumme, Herausgeber, Version), austauschen, neu starten.</summary>
    [RelayCommand(CanExecute = nameof(CanInstallUpdate))]
    private async Task InstallUpdate()
    {
        if (AvailableUpdate is not { } update) return;
        if (update.PackageUrl == null) { OpenUpdate(); return; }
        if (IsScanning) { UpdateStatus = "Bitte erst den laufenden Scan abschließen."; return; }

        IsUpdating = true;
        try
        {
            var progress = new Progress<string>(s => UpdateStatus = s);
            string staging = await AppUpdater.DownloadAndVerifyAsync(update, progress);
            UpdateStatus = "Installiere …";
            if (Monitor.IsRunning) Monitor.Toggle();
            await Task.Run(() => AppUpdater.Apply(staging, AppUpdater.InstallDir));
            AppUpdater.Restart();
            System.Windows.Application.Current.Shutdown();
        }
        catch (Exception ex)
        {
            UpdateStatus = "Update fehlgeschlagen, nichts verändert: " + ex.Message;
            IsUpdating = false;
        }
    }

    [RelayCommand]
    private void OpenUpdate()
    {
        if (AvailableUpdate != null)
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(AvailableUpdate.Url) { UseShellExecute = true });
    }

    [RelayCommand]
    private void Navigate(string page)
    {
        CurrentPage = page switch
        {
            "Findings" => Findings,
            "Timeline" => Timeline,
            "Processes" => Processes,
            "Monitor" => Monitor,
            "Hardening" => Hardening,
            "Quarantine" => Quarantine,
            "Settings" => SettingsPage,
            _ => Dashboard,
        };
        if (CurrentPage == Processes && Processes.Rows.Count == 0) Processes.RefreshCommand.Execute(null);
        if (CurrentPage == Quarantine) Quarantine.RefreshCommand.Execute(null);
        if (CurrentPage == Timeline) Timeline.Reload();
        if (CurrentPage == Hardening && !Hardening.Loaded) Hardening.RefreshCommand.Execute(null);
    }

    public void ShowFinding(FindingItemViewModel item)
    {
        Findings.Reveal(item);
        Navigate("Findings");
    }

    public void ShowMonitorEvent(FindingItemViewModel item)
    {
        Monitor.Selected = Monitor.Events.FirstOrDefault(e => e.Item == item);
        Navigate("Monitor");
    }

    private bool CanScan() => !IsScanning;

    [RelayCommand(CanExecute = nameof(CanScan))]
    private Task StartQuickScan() => RunScan(ScanProfile.Quick);

    [RelayCommand(CanExecute = nameof(CanScan))]
    private Task StartFullScan() => RunScan(ScanProfile.Full);

    [RelayCommand]
    private void CancelScan() => _cts?.Cancel();

    private async Task RunScan(ScanProfile profile)
    {
        IsScanning = true;
        ScanPercent = 0;
        ScanStatus = profile == ScanProfile.Full ? "Vollständiger Scan läuft …" : "Schnellscan läuft …";
        _cts = new CancellationTokenSource();

        var progress = new Progress<ScanProgress>(p =>
        {
            if (p.ScannerCount > 0) ScanPercent = Math.Min(100, p.ScannerIndex * 100.0 / p.ScannerCount);
            ScanStep = string.IsNullOrEmpty(p.ScannerName) ? p.Message : $"{p.ScannerName}: {p.Message}";
        });

        try
        {
            if (Settings.OnlineFeatures)
            {
                ScanStep = "Prüfe auf neue Erkennungsregeln …";
                RulesStatus = await OnlineUpdates.UpdateRulesAsync(_cts.Token);
            }
            var engine = new ScanEngine(ScannerCatalog.CreateAll());
            var report = await engine.RunAsync(Settings.ToScanOptions(profile), progress, _cts.Token);
            report.NewerVersionAvailable = AvailableUpdate?.Latest.ToString(3);
            LastReport = report;
            Findings.Load(report);
            Timeline.Reload();
            Dashboard.Update(report);
            SaveReport(report);
            ScanStatus = report.Cancelled ? "Scan abgebrochen – Teilergebnis." : $"Scan abgeschlossen: {report.Findings.Count(f => f.Severity >= Severity.Low)} relevante Funde.";
        }
        catch (Exception ex)
        {
            ScanStatus = "Scan fehlgeschlagen: " + ex.Message;
        }
        finally
        {
            ScanPercent = 100;
            ScanStep = "";
            IsScanning = false;
        }
    }

    private static readonly JsonSerializerOptions ReportJson = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

    private static void SaveReport(ScanReport report)
    {
        try
        {
            string file = Path.Combine(AppPaths.ReportsDir, $"scan_{report.StartedAt:yyyyMMdd_HHmmss}.json");
            File.WriteAllText(file, JsonSerializer.Serialize(report, ReportJson));
        }
        catch { }
    }
}
