using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ScanMe.Core.Hardening;
using ScanMe.Core.Util;

namespace ScanMe.App.ViewModels;

public sealed partial class HardeningItemViewModel : ObservableObject
{
    private readonly HardeningViewModel _owner;

    public HardeningItemViewModel(HardeningViewModel owner, HardeningItem item)
    {
        _owner = owner;
        Item = item;
    }

    public HardeningItem Item { get; }
    public string Title => Item.Title;
    public string Plain => Item.Plain;
    public string Protects => Item.Protects;
    public string? DevNote => Item.DevNote;
    public bool SupportsAudit => Item.SupportsAudit;
    public string RecommendedText => Item.Recommended is { } r ? $"Empfohlen: {HardeningService.Text(r)}" : "Optional – nur bei Bedarf";
    public string? RebootNote => Item.NeedsReboot ? "Wirkt nach einem Neustart." : null;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(StateText), nameof(IsOn), nameof(IsAudit), nameof(IsOff), nameof(MeetsRecommendation))]
    private HardeningState _state = HardeningState.Unknown;

    public string StateText => HardeningService.Text(State).ToUpperInvariant();
    public bool IsOn => State == HardeningState.On;
    public bool IsAudit => State == HardeningState.Audit;
    public bool IsOff => State == HardeningState.Off;
    public bool MeetsRecommendation => Item.Recommended is not { } r || State == HardeningState.NotAvailable || HardeningService.Satisfies(State, r);

    // Laufender Vorgang an genau diesem Eintrag (z. B. Sysmon-Download und -Installation)
    [ObservableProperty] private bool _isWorking;
    [ObservableProperty] private string _workingText = "";

    [RelayCommand] private Task SetOn() => _owner.ApplyAsync(this, HardeningMode.On);
    [RelayCommand] private Task SetAudit() => _owner.ApplyAsync(this, HardeningMode.Audit);
    [RelayCommand] private Task SetOff() => _owner.ApplyAsync(this, HardeningMode.Off);
}

public sealed partial class HardeningViewModel : ObservableObject
{
    public HardeningViewModel()
    {
        foreach (var item in HardeningCatalog.All) Items.Add(new HardeningItemViewModel(this, item));
    }

    public ObservableCollection<HardeningItemViewModel> Items { get; } = new();
    public ObservableCollection<AuditHit> Hits { get; } = new();
    public bool IsElevated { get; } = SystemEnv.IsElevated;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsIdle))] private bool _isBusy;
    public bool IsIdle => !IsBusy;
    [ObservableProperty] private string? _message;
    [ObservableProperty] private string _summary = "Wird geladen …";
    [ObservableProperty] private bool _loaded;

    public IEnumerable<IGrouping<string, HardeningItemViewModel>> Groups => Items.GroupBy(i => i.Item.Group);

    [RelayCommand]
    public async Task Refresh()
    {
        if (IsBusy) return;
        IsBusy = true;
        var states = await Task.Run(() => Items.Select(i => (i, i.Item.Read())).ToList());
        foreach (var (vm, state) in states) vm.State = state;
        var hits = await Task.Run(() => HardeningService.RecentHits());
        Hits.Clear();
        foreach (var h in hits.Take(100)) Hits.Add(h);
        UpdateSummary();
        Loaded = true;
        IsBusy = false;
    }

    private void UpdateSummary()
    {
        var recommended = Items.Where(i => i.Item.Recommended != null && i.State != HardeningState.NotAvailable).ToList();
        int ok = recommended.Count(i => i.MeetsRecommendation);
        Summary = $"{ok} von {recommended.Count} empfohlenen Schutzmaßnahmen sind eingerichtet.";
    }

    public async Task ApplyAsync(HardeningItemViewModel vm, HardeningMode mode)
    {
        if (!IsElevated) { Message = "✖ Dafür muss ScanMe als Administrator laufen."; return; }
        if (mode == HardeningMode.On && vm.DevNote != null &&
            MessageBox.Show($"{vm.Title} aktivieren?\n\nHinweis: {vm.DevNote}" +
                            (vm.SupportsAudit ? "\n\nTipp: Mit „Testmodus“ sehen Sie erst, was blockiert würde, ohne dass etwas blockiert wird." : ""),
                "ScanMe – Schutz aktivieren", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        IsBusy = true;
        vm.WorkingText = mode == HardeningMode.Off ? "Wird ausgeschaltet …"
            : vm.Item.Id == "log:sysmon" ? "Lädt von Microsoft und installiert …"
            : "Wird eingerichtet …";
        vm.IsWorking = true;
        var result = await Task.Run(() => HardeningService.Apply(vm.Item, mode));
        vm.State = await Task.Run(() => vm.Item.Read());
        vm.IsWorking = false;
        Message = (result.Success ? "✔ " : "✖ ") + result.Message;
        UpdateSummary();
        IsBusy = false;
        // Fehler nicht nur oben auf der Seite melden – dort sieht man sie beim Scrollen nicht.
        if (!result.Success)
            MessageBox.Show(result.Message, "ScanMe – Schutz konnte nicht geändert werden", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    [RelayCommand]
    private async Task ApplyRecommended()
    {
        if (!IsElevated) { Message = "✖ Dafür muss ScanMe als Administrator laufen."; return; }
        if (MessageBox.Show(
                "Alle empfohlenen Schutzmaßnahmen einrichten?\n\n" +
                "• Regeln, die Entwicklerwerkzeuge stören könnten, starten im TESTMODUS: Sie blockieren nichts, sondern protokollieren nur, was sie blockiert hätten.\n" +
                "• Alles wird im Verlauf gespeichert und kann einzeln rückgängig gemacht werden.\n" +
                "• Einige Maßnahmen wirken erst nach einem Neustart.",
                "ScanMe – Schutz einrichten", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        IsBusy = true;
        var results = await Task.Run(HardeningService.ApplyRecommended);
        IsBusy = false;
        int failed = results.Count(r => !r.Success);
        Message = results.Count == 0 ? "✔ Alle empfohlenen Maßnahmen waren bereits eingerichtet."
            : failed == 0 ? $"✔ {results.Count} Schutzmaßnahmen eingerichtet. Einige wirken nach dem nächsten Neustart."
            : $"⚠ {results.Count - failed} eingerichtet, {failed} fehlgeschlagen: " + string.Join(" | ", results.Where(r => !r.Success).Select(r => r.Message));
        await Refresh();
    }

    [RelayCommand]
    private void OpenDefenderSettings() =>
        Process.Start(new ProcessStartInfo("windowsdefender://threatsettings") { UseShellExecute = true });
}
