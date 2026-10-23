using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ScanMe.Core.Scanners;

namespace ScanMe.App.ViewModels;

public sealed partial class ScannerToggle : ObservableObject
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string Description { get; init; }
    public required bool InQuickScan { get; init; }
    [ObservableProperty] private bool _enabled;
}

public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly MainViewModel _main;

    public SettingsViewModel(MainViewModel main)
    {
        _main = main;
        var s = main.Settings;
        _useDefender = s.UseDefender;
        _eventLogDays = s.EventLogDays;
        _minimizeToTray = s.MinimizeToTray;
        _startMonitorOnLaunch = s.StartMonitorOnLaunch;
        _extraPaths = string.Join(Environment.NewLine, s.ExtraPaths);
        foreach (var sc in ScannerCatalog.CreateAll())
            Scanners.Add(new ScannerToggle { Id = sc.Id, Name = sc.Name, Description = sc.Description, InQuickScan = sc.InQuickScan, Enabled = !s.DisabledScanners.Contains(sc.Id) });
    }

    public ObservableCollection<ScannerToggle> Scanners { get; } = new();

    [ObservableProperty] private bool _useDefender;
    [ObservableProperty] private int _eventLogDays;
    [ObservableProperty] private bool _minimizeToTray;
    [ObservableProperty] private bool _startMonitorOnLaunch;
    [ObservableProperty] private string _extraPaths;
    [ObservableProperty] private string? _message;

    [RelayCommand]
    private void Save()
    {
        var s = _main.Settings;
        s.UseDefender = UseDefender;
        s.EventLogDays = Math.Clamp(EventLogDays, 1, 365);
        s.MinimizeToTray = MinimizeToTray;
        s.StartMonitorOnLaunch = StartMonitorOnLaunch;
        s.ExtraPaths = ExtraPaths.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        s.DisabledScanners = Scanners.Where(x => !x.Enabled).Select(x => x.Id).ToList();
        s.Save();
        Message = "✔ Einstellungen gespeichert.";
    }
}
