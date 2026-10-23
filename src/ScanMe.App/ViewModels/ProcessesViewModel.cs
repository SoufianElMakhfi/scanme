using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ScanMe.Core.Actions;
using ScanMe.Core.Engine;
using ScanMe.Core.Inventory;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Models;
using ScanMe.Core.Trust;
using ScanMe.Core.Util;

namespace ScanMe.App.ViewModels;

/// <summary>Eine Zeile der Prozessansicht – inklusive Vertrauens- und Risikobewertung.</summary>
public sealed class ProcessRow
{
    public int Pid { get; init; }
    public int ParentPid { get; init; }
    public string Name { get; init; } = "";
    public string ParentName { get; init; } = "";
    public string? Path { get; init; }
    public string? CommandLine { get; init; }
    public string Publisher { get; init; } = "";
    public string SignatureText { get; init; } = "";
    public bool Signed { get; init; }
    public bool WindowsComponent { get; init; }
    public double Cpu { get; init; }
    public long Ram { get; init; }
    public string RamText => TextUtil.FormatBytes(Ram);
    public bool HasWindow { get; init; }
    public string WindowText => HasWindow ? "sichtbar" : "unsichtbar";
    public bool IsService { get; init; }
    public int Connections { get; init; }
    public string Started { get; init; } = "";
    public int Score { get; init; }
    public Severity Severity { get; init; }
    public string? Sha256 { get; init; }
    public string Indicators { get; init; } = "";
    public string Description { get; init; } = "";
}

public sealed partial class ProcessesViewModel : ObservableObject
{
    public ProcessesViewModel()
    {
        View = CollectionViewSource.GetDefaultView(Rows);
        View.Filter = o => o is ProcessRow r && Matches(r);
        View.SortDescriptions.Add(new SortDescription(nameof(ProcessRow.Score), ListSortDirection.Descending));
        View.SortDescriptions.Add(new SortDescription(nameof(ProcessRow.Name), ListSortDirection.Ascending));
    }

    public ObservableCollection<ProcessRow> Rows { get; } = new();
    public ICollectionView View { get; }

    [ObservableProperty] private ProcessRow? _selected;
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string _search = "";
    [ObservableProperty] private bool _onlySuspicious;
    [ObservableProperty] private bool _onlyHidden;
    [ObservableProperty] private bool _hideWindows;
    [ObservableProperty] private string _summary = "";
    [ObservableProperty] private string? _message;

    partial void OnSearchChanged(string value) => View.Refresh();
    partial void OnOnlySuspiciousChanged(bool value) => View.Refresh();
    partial void OnOnlyHiddenChanged(bool value) => View.Refresh();
    partial void OnHideWindowsChanged(bool value) => View.Refresh();

    private bool Matches(ProcessRow r)
    {
        if (OnlySuspicious && r.Score < 15) return false;
        if (OnlyHidden && r.HasWindow) return false;
        if (HideWindows && r.WindowsComponent) return false;
        if (string.IsNullOrWhiteSpace(Search)) return true;
        string s = Search.Trim();
        return r.Name.Contains(s, StringComparison.OrdinalIgnoreCase) || r.Pid.ToString() == s
               || (r.Path?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false) || r.Publisher.Contains(s, StringComparison.OrdinalIgnoreCase);
    }

    [RelayCommand]
    private async Task Refresh()
    {
        if (IsLoading) return;
        IsLoading = true;
        Message = null;
        try
        {
            var rows = await Task.Run(BuildRows);
            Rows.Clear();
            foreach (var r in rows) Rows.Add(r);
            int hidden = rows.Count(r => !r.HasWindow);
            Summary = $"{rows.Count} Prozesse · {hidden} ohne sichtbares Fenster · {rows.Count(r => r.WindowsComponent)} Windows-Komponenten · " +
                      $"{rows.Count(r => !r.Signed)} unsigniert · {rows.Count(r => r.Score >= 15)} auffällig";
        }
        finally { IsLoading = false; }
    }

    private static List<ProcessRow> BuildRows()
    {
        var snap = ProcessSnapshot.Capture(measureCpu: true, crossView: false);
        var conns = ConnectionTable.Capture().Where(c => c.IsEstablished && c.IsExternal).GroupBy(c => c.Pid).ToDictionary(g => g.Key, g => g.Count());
        var rows = new List<ProcessRow>();
        foreach (var p in snap.Processes.Values)
        {
            var f = new Finding { ScannerId = "live", Category = FindingCategory.Process, Title = p.Name };
            FileTrustInfo? info = null;
            if (p.ImagePath != null) info = ExecutableAssessor.Assess(f, p.ImagePath, FileTrustService.Shared, addActions: false);
            foreach (var rule in CommandLineRules.Match(p.CommandLine))
                f.AddIndicator(rule.Id, rule.Text, rule.Weight);
            RiskScorer.Finalize(f);

            var parent = snap.Get(p.ParentPid);
            bool pseudo = SystemProcesses.IsKernelPseudoProcess(p.Name, p.Pid);
            rows.Add(new ProcessRow
            {
                Pid = p.Pid,
                ParentPid = p.ParentPid,
                Name = p.Name,
                ParentName = parent?.Name ?? "–",
                Path = p.ImagePath,
                CommandLine = p.CommandLine,
                Publisher = pseudo ? "Windows-Kernel" : info?.Signer ?? info?.CompanyName ?? (p.ImagePath == null ? "(kein Zugriff)" : "Unbekannt"),
                SignatureText = pseudo ? "Kernel" : info?.SignatureStatusText ?? "–",
                Signed = pseudo || info?.Signature == SignatureState.Valid,
                WindowsComponent = pseudo || info?.IsWindowsComponent == true,
                Cpu = Math.Round(p.CpuPercent, 1),
                Ram = p.WorkingSet,
                HasWindow = p.HasVisibleWindow,
                IsService = p.IsService,
                Connections = conns.GetValueOrDefault(p.Pid),
                Started = p.StartTime?.ToString("g") ?? "",
                Score = pseudo ? 0 : f.Score,
                Severity = pseudo ? Severity.Info : f.Severity,
                Sha256 = info?.Sha256,
                Indicators = string.Join("\n", f.Indicators.Where(i => i.Weight != 0).OrderByDescending(i => i.Weight).Select(i => $"{(i.Weight > 0 ? "+" : "")}{i.Weight}  {i.Text}")),
                Description = info?.FileDescription ?? "",
            });
        }
        return rows;
    }

    [RelayCommand]
    private async Task Kill()
    {
        if (Selected == null) return;
        string? block = SafetyGuard.CheckProcess(Selected.Pid);
        if (block != null) { Message = "✖ " + block; return; }
        if (MessageBox.Show($"Prozess {Selected.Name} (PID {Selected.Pid}) beenden?", "ScanMe", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        try
        {
            using var p = Process.GetProcessById(Selected.Pid);
            p.Kill();
            Message = $"✔ {Selected.Name} beendet.";
            await Refresh();
        }
        catch (Exception ex) { Message = "✖ " + ex.Message; }
    }

    [RelayCommand]
    private void OpenLocation()
    {
        if (Selected?.Path is { } path && File.Exists(path))
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
    }

    [RelayCommand]
    private void VirusTotal()
    {
        if (Selected?.Sha256 is { } hash)
            Process.Start(new ProcessStartInfo($"https://www.virustotal.com/gui/file/{hash}") { UseShellExecute = true });
    }

    [RelayCommand]
    private async Task QuarantineFile()
    {
        if (Selected?.Path is not { } path) return;
        string? block = SafetyGuard.CheckFile(path);
        if (block != null) { Message = "✖ " + block; return; }
        if (MessageBox.Show($"Prozess beenden und Datei in Quarantäne verschieben?\n\n{path}", "ScanMe", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        var result = await Task.Run(() => Quarantine.Add(path, "Manuell aus Prozessansicht"));
        Message = (result.Success ? "✔ " : "✖ ") + result.Message;
        await Refresh();
    }
}
