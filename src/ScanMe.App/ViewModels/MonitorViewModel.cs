using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ScanMe.Core.Models;
using ScanMe.Core.Monitoring;

namespace ScanMe.App.ViewModels;

public sealed class MonitorEventItem
{
    public required MonitorEvent Event { get; init; }
    public required FindingItemViewModel Item { get; init; }
    public string Time => Event.Time.ToString("HH:mm:ss");
    public string KindText => Event.Kind switch
    {
        MonitorKind.Process => "Prozess",
        MonitorKind.Autostart => "Autostart",
        MonitorKind.File => "Datei",
        MonitorKind.Network => "Netzwerk",
        _ => "System",
    };
}

public sealed partial class MonitorViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    private readonly RealtimeMonitor _monitor = new();

    public MonitorViewModel(MainViewModel main)
    {
        _main = main;
        View = CollectionViewSource.GetDefaultView(Events);
        View.Filter = o => o is MonitorEventItem e && (!OnlyAlerts || e.Item.Severity >= Severity.Low);
        _monitor.Detected += OnDetected;
        _monitor.StatusChanged += s => Application.Current?.Dispatcher.BeginInvoke(() => Status = s);
    }

    public ObservableCollection<MonitorEventItem> Events { get; } = new();
    public ICollectionView View { get; }

    /// <summary>Wird von der Tray-Komponente fuer Benachrichtigungen abonniert.</summary>
    public event Action<FindingItemViewModel>? Alert;

    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private bool _onlyAlerts = true;
    [ObservableProperty] private string _status = "Überwachung ist aus.";
    [ObservableProperty] private int _alertCount;
    [ObservableProperty] private int _eventCount;
    [ObservableProperty] private MonitorEventItem? _selected;

    partial void OnOnlyAlertsChanged(bool value) => View.Refresh();

    [RelayCommand]
    public void Toggle()
    {
        if (_monitor.IsRunning) _monitor.Stop(); else _monitor.Start();
        IsRunning = _monitor.IsRunning;
    }

    [RelayCommand]
    private void Clear()
    {
        Events.Clear();
        AlertCount = 0;
        EventCount = 0;
    }

    private void OnDetected(MonitorEvent e)
    {
        Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            var item = new MonitorEventItem { Event = e, Item = new FindingItemViewModel(e.Finding) };
            Events.Insert(0, item);
            while (Events.Count > 1000) Events.RemoveAt(Events.Count - 1);
            EventCount++;
            if (e.Finding.Severity >= Severity.Low) AlertCount++;
            if (e.Finding.Severity >= Severity.Medium) Alert?.Invoke(item.Item);
        });
    }

    public void Shutdown() => _monitor.Dispose();
}
