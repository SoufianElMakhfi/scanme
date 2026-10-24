using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ScanMe.Core.Engine;
using ScanMe.Core.Models;

namespace ScanMe.App.ViewModels;

public sealed class TimelineItem
{
    public required FindingItemViewModel Item { get; init; }
    public required DateTime When { get; init; }
    public required bool DayOnly { get; init; }
    public string What => Item.Finding.OccurredWhat ?? "";
    public string TimeText => DayOnly ? "—" : When.ToString("HH:mm");
    public string DayText => When.Date == DateTime.Today ? "Heute" : When.Date == DateTime.Today.AddDays(-1) ? "Gestern"
        : When.ToString("dddd, d. MMMM yyyy", CultureInfo.GetCultureInfo("de-DE"));

    /// <summary>Teil einer Haeufung auffaelliger Ereignisse.</summary>
    public bool InCluster { get; init; }

    /// <summary>Nur am juengsten (obersten) Ereignis einer Haeufung: Hinweistext ueber der Zeile.</summary>
    public string? ClusterHint { get; init; }
}

public sealed partial class TimelineViewModel : ObservableObject
{
    private readonly MainViewModel _main;

    public TimelineViewModel(MainViewModel main)
    {
        _main = main;
        View = CollectionViewSource.GetDefaultView(Items);
        View.GroupDescriptions.Add(new PropertyGroupDescription(nameof(TimelineItem.DayText)));
    }

    public ObservableCollection<TimelineItem> Items { get; } = new();
    public ICollectionView View { get; }

    [ObservableProperty] private TimelineItem? _selected;
    [ObservableProperty] private bool _hasReport;
    [ObservableProperty] private int _untimedCount;
    [ObservableProperty] private int _clusterCount;
    [ObservableProperty] private string _summary = "";
    [ObservableProperty] private bool _missingEventLog;

    // Zeitraum (genau einer aktiv)
    [ObservableProperty] private bool _rangeDay;
    [ObservableProperty] private bool _rangeWeek = true;
    [ObservableProperty] private bool _rangeMonth;
    [ObservableProperty] private bool _rangeAll;
    [ObservableProperty] private bool _onlyNotable;
    [ObservableProperty] private bool _showInfo;

    partial void OnRangeDayChanged(bool value) { if (value) Reload(); }
    partial void OnRangeWeekChanged(bool value) { if (value) Reload(); }
    partial void OnRangeMonthChanged(bool value) { if (value) Reload(); }
    partial void OnRangeAllChanged(bool value) { if (value) Reload(); }
    partial void OnOnlyNotableChanged(bool value) => Reload();
    partial void OnShowInfoChanged(bool value) => Reload();

    private DateTime? Since => RangeDay ? DateTime.Now.AddDays(-1) : RangeWeek ? DateTime.Now.AddDays(-7) : RangeMonth ? DateTime.Now.AddDays(-30) : null;

    /// <summary>Neu aufbauen – nach einem Scan und beim Oeffnen der Seite (Ignorieren kann sich geaendert haben).</summary>
    public void Reload()
    {
        var report = _main.LastReport;
        HasReport = report != null;
        MissingEventLog = report != null && !report.ScannerResults.Any(r => r.ScannerId == "eventlog");

        var byFinding = _main.Findings.AllItems.ToDictionary(i => i.Finding);
        var visible = _main.Findings.AllItems
            .Where(i => !i.IsIgnored)
            .Where(i => ShowInfo || i.Verdict != Verdict.Info)
            .Where(i => !OnlyNotable || Timeline.IsNotable(i.Finding))
            .ToList();
        var since = Since;
        UntimedCount = visible.Count(i => i.Finding.OccurredAt == null);

        // Haeufungen ueber alle sichtbaren Funde bilden, damit eine Kette am Rand des Zeitraums nicht zerschnitten wird.
        var result = Timeline.Build(visible.Select(i => i.Finding));
        var clusters = result.Clusters.ToDictionary(c => c.Id);
        var hinted = new HashSet<int>();

        var previous = Selected?.Item;
        Items.Clear();
        foreach (var e in result.Entries)
        {
            var when = e.Finding.OccurredAt!.Value;
            if (since != null && when < since) continue;
            string? hint = null;
            if (e.Cluster != 0 && hinted.Add(e.Cluster))
            {
                var c = clusters[e.Cluster];
                var span = c.To - c.From;
                hint = $"{c.NotableCount} auffällige Ereignisse innerhalb {(span.TotalMinutes < 1 ? "einer Minute" : $"von {Math.Ceiling(span.TotalMinutes):0} Minuten")} " +
                       "– hängen sie zusammen?";
            }
            Items.Add(new TimelineItem
            {
                Item = byFinding[e.Finding],
                When = when,
                DayOnly = e.Finding.OccurredDayOnly,
                InCluster = e.Cluster != 0,
                ClusterHint = hint,
            });
        }
        ClusterCount = hinted.Count;
        Summary = Items.Count == 0 ? "" : $"{Items.Count} Ereignisse" + (ClusterCount > 0 ? $" · {ClusterCount} Häufung{(ClusterCount == 1 ? "" : "en")}" : "");
        Selected = Items.FirstOrDefault(i => i.Item == previous) ?? Items.FirstOrDefault(i => i.InCluster) ?? Items.FirstOrDefault();
    }

    [RelayCommand]
    private void OpenFinding()
    {
        if (Selected != null) _main.ShowFinding(Selected.Item);
    }
}
