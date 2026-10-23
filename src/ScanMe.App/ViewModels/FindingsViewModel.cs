using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using ScanMe.Core.Models;
using ScanMe.Core.Reporting;

namespace ScanMe.App.ViewModels;

public sealed partial class FindingsViewModel : ObservableObject
{
    private readonly MainViewModel _main;

    public FindingsViewModel(MainViewModel main)
    {
        _main = main;
        View = CollectionViewSource.GetDefaultView(AllItems);
        View.Filter = Filter;
        Categories = new[] { "Alle Kategorien" }.Concat(Enum.GetValues<FindingCategory>().Select(c => c.German())).ToList();
    }

    public ObservableCollection<FindingItemViewModel> AllItems { get; } = new();
    public ICollectionView View { get; }
    public IReadOnlyList<string> Categories { get; }

    [ObservableProperty] private FindingItemViewModel? _selectedItem;
    [ObservableProperty] private string _search = "";
    [ObservableProperty] private string _selectedCategory = "Alle Kategorien";
    [ObservableProperty] private bool _showCritical = true;
    [ObservableProperty] private bool _showHigh = true;
    [ObservableProperty] private bool _showMedium = true;
    [ObservableProperty] private bool _showLow = true;
    [ObservableProperty] private bool _showInfo;
    [ObservableProperty] private bool _showIgnored;
    [ObservableProperty] private int _visibleCount;
    [ObservableProperty] private string? _exportMessage;

    partial void OnSearchChanged(string value) => Refresh();
    partial void OnSelectedCategoryChanged(string value) => Refresh();
    partial void OnShowCriticalChanged(bool value) => Refresh();
    partial void OnShowHighChanged(bool value) => Refresh();
    partial void OnShowMediumChanged(bool value) => Refresh();
    partial void OnShowLowChanged(bool value) => Refresh();
    partial void OnShowInfoChanged(bool value) => Refresh();
    partial void OnShowIgnoredChanged(bool value) => Refresh();

    public void Load(ScanReport report)
    {
        AllItems.Clear();
        foreach (var f in report.Findings) AllItems.Add(new FindingItemViewModel(f));
        Refresh();
        SelectedItem = View.Cast<FindingItemViewModel>().FirstOrDefault();
    }

    private void Refresh()
    {
        View.Refresh();
        VisibleCount = View.Cast<object>().Count();
    }

    private bool Filter(object o)
    {
        if (o is not FindingItemViewModel i) return false;
        if (i.IsIgnored && !ShowIgnored) return false;
        bool sev = i.Severity switch
        {
            Severity.Critical => ShowCritical,
            Severity.High => ShowHigh,
            Severity.Medium => ShowMedium,
            Severity.Low => ShowLow,
            _ => ShowInfo,
        };
        if (!sev) return false;
        if (SelectedCategory != "Alle Kategorien" && i.Category.German() != SelectedCategory) return false;
        if (!string.IsNullOrWhiteSpace(Search))
        {
            string s = Search.Trim();
            return i.Title.Contains(s, StringComparison.OrdinalIgnoreCase)
                   || i.Description.Contains(s, StringComparison.OrdinalIgnoreCase)
                   || (i.Finding.FilePath?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false)
                   || i.Finding.Details.Values.Any(v => v.Contains(s, StringComparison.OrdinalIgnoreCase));
        }
        return true;
    }

    [RelayCommand]
    private void ExportHtml()
    {
        if (_main.LastReport == null) return;
        var dlg = new SaveFileDialog
        {
            Filter = "HTML-Bericht (*.html)|*.html|JSON (*.json)|*.json",
            FileName = $"ScanMe_{_main.LastReport.MachineName}_{_main.LastReport.StartedAt:yyyy-MM-dd_HHmm}.html",
        };
        if (dlg.ShowDialog() != true) return;
        bool includeIgnored = ShowIgnored;
        var findings = _main.LastReport.Findings.Where(f => includeIgnored || !Core.Actions.IgnoreList.IsIgnored(f)).ToList();
        if (dlg.FileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            File.WriteAllText(dlg.FileName, ReportWriter.ToJson(_main.LastReport));
        else
            File.WriteAllText(dlg.FileName, ReportWriter.ToHtml(_main.LastReport, findings));
        ExportMessage = $"Gespeichert: {dlg.FileName}";
        if (dlg.FileName.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
            Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
    }
}
