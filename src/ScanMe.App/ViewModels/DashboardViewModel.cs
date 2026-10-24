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

    [RelayCommand]
    private async Task StartOfflineScan()
    {
        if (!_main.IsElevated) { BaselineMessage = "✖ Die Offline-Prüfung braucht Adminrechte."; return; }
        if (System.Windows.MessageBox.Show(
                "Microsoft Defender Offline-Prüfung starten?\n\n" +
                "• Der PC startet IN KÜRZE NEU – bitte vorher alles speichern und Programme schließen.\n" +
                "• Defender prüft den PC, bevor Windows lädt. Dort können sich auch Rootkits nicht verstecken.\n" +
                "• Dauer ca. 15 Minuten, danach startet Windows normal. Ergebnisse stehen in Windows-Sicherheit → Schutzverlauf und beim nächsten ScanMe-Scan.",
                "ScanMe – Offline-Prüfung", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Warning) != System.Windows.MessageBoxResult.Yes)
            return;
        var result = await Task.Run(Core.Actions.OfflineScan.Start);
        BaselineMessage = (result.Success ? "✔ " : "✖ ") + result.Message;
    }

    // ------------------------------------------------------------------
    // Sauberer Zustand (Baseline)
    // ------------------------------------------------------------------

    [ObservableProperty] private string _baselineText = BaselineStatus();
    [ObservableProperty] private string? _baselineMessage;

    private static string BaselineStatus()
    {
        var b = Core.Baseline.BaselineService.Load();
        if (b == null) return "Noch nicht gespeichert. Am besten direkt nach einer Windows-Neuinstallation speichern – danach meldet ScanMe jede Veränderung.";
        return Core.Baseline.BaselineService.IsIntact(b)
            ? $"Gespeichert am {b.CreatedAt:g}. Jeder Scan zeigt zuerst, was sich seitdem verändert hat."
            : "⚠ Die gespeicherte Datei wurde nachträglich verändert – bitte mit Ihrer USB-Sicherung vergleichen.";
    }

    [RelayCommand]
    private async Task SaveBaseline()
    {
        if (!_main.IsElevated)
        {
            BaselineMessage = "✖ Bitte ScanMe als Administrator starten – sonst fehlen Aufgaben und Defender-Ausnahmen im sauberen Zustand.";
            return;
        }
        if (System.Windows.MessageBox.Show(
                "Den aktuellen Zustand als SAUBER speichern?\n\n" +
                "Nur tun, wenn der PC nachweislich sauber ist – ideal direkt nach einer Windows-Neuinstallation und den ersten eigenen Programmen.\n\n" +
                "Alles, was jetzt vorhanden ist, gilt danach als bekannt und wird nicht mehr als Änderung gemeldet.",
                "ScanMe – Sauberer Zustand", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Warning) != System.Windows.MessageBoxResult.Yes)
            return;
        var snap = await Task.Run(Core.Baseline.BaselineService.Capture);
        Core.Baseline.BaselineService.Save(snap);
        BaselineText = BaselineStatus();
        BaselineMessage = $"✔ Gespeichert ({snap.Categories.Sum(c => c.Value.Count)} Einträge). Tipp: Mit „Auf USB sichern“ eine Kopie außerhalb des PCs ablegen.";
    }

    [RelayCommand]
    private void ExportBaseline()
    {
        if (!File.Exists(Core.Baseline.BaselineService.FilePath)) { BaselineMessage = "✖ Noch kein sauberer Zustand gespeichert."; return; }
        var dlg = new Microsoft.Win32.SaveFileDialog { FileName = $"ScanMe-Baseline-{Environment.MachineName}-{DateTime.Now:yyyy-MM-dd}.json", Filter = "Baseline (*.json)|*.json" };
        if (dlg.ShowDialog() != true) return;
        File.Copy(Core.Baseline.BaselineService.FilePath, dlg.FileName, overwrite: true);
        BaselineMessage = $"✔ Gesichert: {dlg.FileName}. Bewahren Sie die Kopie getrennt vom PC auf (z. B. USB-Stick).";
    }
}
