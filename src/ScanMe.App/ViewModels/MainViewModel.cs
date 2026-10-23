using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ScanMe.Core.Actions;
using ScanMe.Core.Engine;
using ScanMe.Core.Models;
using ScanMe.Core.Scanners;
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
        Processes = new ProcessesViewModel();
        Quarantine = new QuarantineViewModel();
        SettingsPage = new SettingsViewModel(this);
        Monitor = new MonitorViewModel(this);
        _currentPage = Dashboard;
    }

    public MonitorViewModel Monitor { get; }

    public AppSettings Settings { get; }
    public DashboardViewModel Dashboard { get; }
    public FindingsViewModel Findings { get; }
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

    [RelayCommand]
    private void Navigate(string page)
    {
        CurrentPage = page switch
        {
            "Findings" => Findings,
            "Processes" => Processes,
            "Monitor" => Monitor,
            "Quarantine" => Quarantine,
            "Settings" => SettingsPage,
            _ => Dashboard,
        };
        if (CurrentPage == Processes && Processes.Rows.Count == 0) Processes.RefreshCommand.Execute(null);
        if (CurrentPage == Quarantine) Quarantine.RefreshCommand.Execute(null);
    }

    public void ShowFinding(FindingItemViewModel item)
    {
        Findings.SelectedItem = item;
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
            var engine = new ScanEngine(ScannerCatalog.CreateAll());
            var report = await engine.RunAsync(Settings.ToScanOptions(profile), progress, _cts.Token);
            LastReport = report;
            Findings.Load(report);
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
