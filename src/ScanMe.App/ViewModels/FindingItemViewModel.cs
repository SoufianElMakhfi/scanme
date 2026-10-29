using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ScanMe.Core.Actions;
using ScanMe.Core.Engine;
using ScanMe.Core.Models;
using ScanMe.Core.Reporting;

namespace ScanMe.App.ViewModels;

public sealed partial class FindingItemViewModel : ObservableObject
{
    public FindingItemViewModel(Finding finding)
    {
        Finding = finding;
        _isIgnored = IgnoreList.IsIgnored(finding);
        Actions = finding.Actions.Select(a => new ActionItemViewModel(this, a)).ToList();
    }

    public Finding Finding { get; }
    public string Title => Finding.Title;
    public Severity Severity => Finding.Severity;
    public int Score => Finding.Score;
    public FindingCategory Category => Finding.Category;
    public string Description => Finding.Description;
    public string Explanation => Finding.Explanation;
    public string Recommendation => Finding.Recommendation;
    public bool IsProtected => Finding.IsProtected;
    public IReadOnlyList<Indicator> Indicators => Finding.Indicators.Where(i => i.Weight != 0).OrderByDescending(i => i.Weight).ToList();
    public IReadOnlyList<KeyValuePair<string, string>> Details => Finding.Details.ToList();
    public IReadOnlyList<ActionItemViewModel> Actions { get; }
    public string Subtitle => Finding.FilePath ?? Finding.Location ?? "";

    /// <summary>z. B. "Datei erstellt: 14.03.2026 14:02" – leer, wenn der Zeitpunkt unbekannt ist.</summary>
    public string OccurredText => Finding.OccurredAt is { } t
        ? $"{Finding.OccurredWhat}: {(Finding.OccurredDayOnly ? t.ToString("d") : t.ToString("g"))}"
        : "";

    // --- Laienansicht ---
    public Verdict Verdict => Finding.Verdict;
    public string PlainSummary => Finding.PlainSummary;
    // Kopien: Nach einer erneuten Bewertung (z. B. Defender-Pruefung) muss die Liste sichtbar neu geladen werden.
    public IReadOnlyList<string> Questions => Finding.Questions.ToList();
    public bool HasQuestions => Finding.Questions.Count > 0;
    public string IfUnknown => Finding.IfUnknown;

    // --- Wie sicher ist das? ---
    public string Certainty => Finding.Certainty;
    public IReadOnlyList<CheckLine> Checks => FindingText.Ordered(Finding.Checks)
        .Select(c => new CheckLine(c.Symbol, c.Result, $"{c.Source}: {c.Text}")).ToList();
    public bool HasCertainty => Finding.Certainty.Length > 0 || Finding.Checks.Count > 0;

    /// <summary>Selbst nachpruefen: VirusTotal und Defender stehen direkt bei der Einschaetzung, nicht erst in den Details.</summary>
    public IReadOnlyList<ActionItemViewModel> CheckActions =>
        Actions.Where(a => a.Action.Kind is RemediationKind.LookupOnline or RemediationKind.DefenderScanFile).ToList();

    /// <summary>Bei "Handeln" sofort die Schritte zeigen, sonst erst nach "Kenne ich nicht".</summary>
    public bool ShowSteps => Verdict == Verdict.Act || (DontKnow && !string.IsNullOrEmpty(IfUnknown));

    /// <summary>Die wichtigsten (veraendernden) Aktionen fuer den Schritt-Kasten; Infos wie VirusTotal bleiben bei den Details.</summary>
    public IReadOnlyList<ActionItemViewModel> PrimaryActions => Actions.Where(a => a.IsDestructive).ToList();

    [ObservableProperty] private bool _isIgnored;
    [ObservableProperty] private string? _actionMessage;
    [ObservableProperty] private bool _actionSucceeded;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ShowSteps))] private bool _dontKnow;

    partial void OnIsIgnoredChanged(bool value) => IgnoreList.Set(Finding, value);

    [RelayCommand]
    private void KnowIt()
    {
        IsIgnored = true;
        DontKnow = false;
        ActionSucceeded = true;
        ActionMessage = "✔ Als bekannt markiert – dieser Fund wird künftig ausgeblendet (unter „Ignorierte“ wieder sichtbar).";
    }

    [RelayCommand]
    private void DoNotKnow() => DontKnow = true;

    [RelayCommand]
    private void CopyAll()
    {
        try
        {
            Clipboard.SetText(FindingText.ToText(Finding));
            ActionMessage = "✔ Der komplette Fund steht in der Zwischenablage – mit Strg+V z. B. in eine E-Mail einfügen.";
            ActionSucceeded = true;
        }
        catch (Exception ex)
        {
            // Die Zwischenablage kann kurz von einem anderen Programm belegt sein.
            ActionMessage = "✖ Kopieren fehlgeschlagen: " + ex.Message;
            ActionSucceeded = false;
        }
    }

    /// <summary>Nach einer Pruefung durch den Nutzer (z. B. "Mit Defender scannen") Bewertung und Anzeige erneuern.</summary>
    public void Reassess()
    {
        RiskScorer.Finalize(Finding);
        PlainLanguage.Apply(Finding);
        OnPropertyChanged(string.Empty);
    }
}

public sealed record CheckLine(string Symbol, CheckResult Result, string Text);

public sealed partial class ActionItemViewModel : ObservableObject
{
    private readonly FindingItemViewModel _owner;

    public ActionItemViewModel(FindingItemViewModel owner, RemediationAction action)
    {
        _owner = owner;
        Action = action;
    }

    public RemediationAction Action { get; }
    public string Label => Action.Label;
    public bool IsDestructive => Action.Kind is RemediationKind.KillProcess or RemediationKind.QuarantineFile or RemediationKind.DisableService
        or RemediationKind.DeleteRegistryValue or RemediationKind.RemoveWmiSubscription or RemediationKind.DisableScheduledTask
        or RemediationKind.DisableAutostart or RemediationKind.RestoreRegistryValue or RemediationKind.RestoreHostsFile or RemediationKind.RemoveDefenderExclusion;

    [RelayCommand]
    private async Task Execute()
    {
        if (Action.RequiresConfirmation)
        {
            string text = $"{Action.Label}?\n\nBetrifft: {Action.Target}\n\n" +
                          (Action.Kind == RemediationKind.RemoveWmiSubscription
                              ? "Diese Aktion kann NICHT rückgängig gemacht werden."
                              : "Die Änderung wird gesichert und kann unter 'Quarantäne & Verlauf' rückgängig gemacht werden.");
            if (MessageBox.Show(text, "ScanMe – Aktion bestätigen", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;
        }

        _owner.IsBusy = true;
        var result = await ActionExecutor.ExecuteAsync(_owner.Finding, Action);
        _owner.IsBusy = false;
        _owner.ActionSucceeded = result.Success;
        _owner.ActionMessage = (result.Success ? "✔ " : "✖ ") + result.Message;
        if (result.Success && Action.Kind == RemediationKind.DefenderScanFile) _owner.Reassess();
    }
}
