using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ScanMe.Core.Models;

namespace ScanMe.App.ViewModels;

public sealed partial class DashboardViewModel : ObservableObject
{
    private readonly MainViewModel _main;

    public DashboardViewModel(MainViewModel main) => _main = main;

    public MainViewModel Main => _main;

    [ObservableProperty] private bool _hasReport;
    [ObservableProperty] private int _health;
    [ObservableProperty] private string _verdict = "Noch kein Scan durchgeführt";
    [ObservableProperty] private string _verdictDetail = "Starten Sie einen Scan, um zu sehen, was auf diesem PC vor sich geht.";
    [ObservableProperty] private int _critical;
    [ObservableProperty] private int _high;
    [ObservableProperty] private int _medium;
    [ObservableProperty] private int _low;
    [ObservableProperty] private int _info;
    [ObservableProperty] private string _lastScan = "–";

    public ObservableCollection<FindingItemViewModel> TopFindings { get; } = new();
    public ObservableCollection<string> CategorySummary { get; } = new();

    public void Update(ScanReport report)
    {
        var visible = report.Findings.Where(f => !Core.Actions.IgnoreList.IsIgnored(f)).ToList();
        HasReport = true;
        Health = report.HealthScore;
        Critical = visible.Count(f => f.Severity == Severity.Critical);
        High = visible.Count(f => f.Severity == Severity.High);
        Medium = visible.Count(f => f.Severity == Severity.Medium);
        Low = visible.Count(f => f.Severity == Severity.Low);
        Info = visible.Count(f => f.Severity == Severity.Info);
        LastScan = $"{report.FinishedAt:g} · {(report.FinishedAt - report.StartedAt):mm\\:ss} min · {(report.WasElevated ? "mit Adminrechten" : "OHNE Adminrechte (eingeschränkt)")}";

        (Verdict, VerdictDetail) = (Critical, High, Medium) switch
        {
            ( > 0, _, _) => ("Akuter Handlungsbedarf", "Es wurden kritische Funde entdeckt, die auf aktive Schadsoftware oder einen Einbruch hindeuten. Bitte die Funde unten zuerst bearbeiten."),
            (0, > 0, _) => ("Ernsthafte Auffälligkeiten", "Einige Funde sind deutlich verdächtig. Bitte prüfen Sie die Funde mit hoher Priorität."),
            (0, 0, > 0) => ("Einzelne Auffälligkeiten", "Keine akute Bedrohung erkannt, aber einige Punkte sollten Sie sich ansehen."),
            _ => ("Keine Bedrohungen erkannt", "Es wurden keine verdächtigen Aktivitäten gefunden. Optimierungshinweise finden Sie unter 'Funde'."),
        };

        TopFindings.Clear();
        foreach (var item in _main.Findings.AllItems.Where(i => i.Finding.Severity >= Severity.Medium && !i.IsIgnored).Take(6))
            TopFindings.Add(item);

        CategorySummary.Clear();
        foreach (var g in visible.Where(f => f.Severity >= Severity.Low).GroupBy(f => f.Category).OrderByDescending(g => g.Count()))
            CategorySummary.Add($"{g.Key.German()}: {g.Count()}");
    }

    [RelayCommand]
    private void Open(FindingItemViewModel item) => _main.ShowFinding(item);
}
