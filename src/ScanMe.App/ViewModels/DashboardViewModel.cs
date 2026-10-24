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
    // Zaehler nach Laien-Ampel
    [ObservableProperty] private int _actCount;
    [ObservableProperty] private int _checkCount;
    [ObservableProperty] private int _harmlessCount;
    [ObservableProperty] private int _infoCount;
    [ObservableProperty] private string _lastScan = "–";

    public ObservableCollection<FindingItemViewModel> TopFindings { get; } = new();
    public ObservableCollection<string> CategorySummary { get; } = new();

    public void Update(ScanReport report)
    {
        var visible = report.Findings.Where(f => !Core.Actions.IgnoreList.IsIgnored(f)).ToList();
        HasReport = true;
        Health = report.HealthScore;
        ActCount = visible.Count(f => f.Verdict == Core.Models.Verdict.Act);
        CheckCount = visible.Count(f => f.Verdict == Core.Models.Verdict.Check);
        HarmlessCount = visible.Count(f => f.Verdict == Core.Models.Verdict.LikelyHarmless);
        InfoCount = visible.Count(f => f.Verdict == Core.Models.Verdict.Info);
        LastScan = $"{report.FinishedAt:g} · {(report.FinishedAt - report.StartedAt):mm\\:ss} min · {(report.WasElevated ? "mit Adminrechten" : "OHNE Adminrechte (eingeschränkt)")}";

        (Verdict, VerdictDetail) = (ActCount, CheckCount) switch
        {
            ( > 0, _) => ("Bitte handeln",
                $"ScanMe hat {ActCount} Fund(e) mit deutlichen Hinweisen auf Schadsoftware oder einen Angriff entdeckt. Öffnen Sie die roten Funde – dort steht Schritt für Schritt, was zu tun ist."),
            (0, > 0) => ("Kurz prüfen",
                $"Keine eindeutige Bedrohung. {CheckCount} Punkt(e) können harmlos oder gefährlich sein – je nachdem, ob Sie sie selbst veranlasst haben. Beantworten Sie dort die kurzen Fragen."),
            _ => ("Alles in Ordnung",
                "Es wurden keine Hinweise auf Schadsoftware gefunden. Funde mit „wahrscheinlich harmlos“ sind nur zur Information."),
        };

        TopFindings.Clear();
        foreach (var item in _main.Findings.AllItems.Where(i => i.Verdict >= Core.Models.Verdict.Check && !i.IsIgnored).Take(6))
            TopFindings.Add(item);

        CategorySummary.Clear();
        foreach (var g in visible.Where(f => f.Verdict >= Core.Models.Verdict.Check).GroupBy(f => f.Category).OrderByDescending(g => g.Count()))
            CategorySummary.Add($"{g.Key.German()}: {g.Count()}");
    }

    [RelayCommand]
    private void Open(FindingItemViewModel item) => _main.ShowFinding(item);
}
