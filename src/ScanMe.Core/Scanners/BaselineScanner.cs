using ScanMe.Core.Baseline;
using ScanMe.Core.Engine;
using ScanMe.Core.Models;
using ScanMe.Core.Util;

namespace ScanMe.Core.Scanners;

/// <summary>Meldet alle Aenderungen seit dem gespeicherten sauberen Zustand (Baseline).</summary>
public sealed class BaselineScanner : IScanner
{
    public string Id => "baseline";
    public string Name => "Änderungen seit sauberem Zustand";
    public string Description => "Vergleicht Autostarts, Dienste, Treiber, Aufgaben, Ausnahmen, Konten, Programme und Zertifikate mit dem gespeicherten sauberen Zustand.";
    public bool InQuickScan => true;

    /// <summary>Kategorien, in denen Neues besonders verdaechtig ist (Einnistung/Rechte).</summary>
    private static readonly Dictionary<string, int> Weight = new()
    {
        [BaselineService.CatAutostart] = 25, [BaselineService.CatService] = 25, [BaselineService.CatDriver] = 30,
        [BaselineService.CatTask] = 20, [BaselineService.CatExclusion] = 40, [BaselineService.CatAdmin] = 45,
        [BaselineService.CatAccount] = 30, [BaselineService.CatRootCert] = 35, [BaselineService.CatWmi] = 50,
        [BaselineService.CatHosts] = 35, [BaselineService.CatBrowserExt] = 20, [BaselineService.CatSoftware] = 10,
    };

    public Task ScanAsync(ScanContext ctx)
    {
        var baseline = BaselineService.Load();
        if (baseline == null)
        {
            var info = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.SecurityConfig,
                Title = "Kein sauberer Zustand gespeichert",
                Description = "Für diesen PC wurde noch keine Baseline gespeichert.",
                Explanation = "Mit einem gespeicherten sauberen Zustand meldet ScanMe künftig genau, was sich danach verändert hat – die zuverlässigste Methode, neue Einnistungen zu erkennen.",
                Recommendation = "Direkt nach einer Windows-Neuinstallation (oder wenn der PC nachweislich sauber ist) in der Übersicht „Zustand als sauber merken“ klicken.",
            };
            ctx.Add(info);
            return Task.CompletedTask;
        }

        ctx.Status("Vergleiche mit sauberem Zustand …");
        if (!BaselineService.IsIntact(baseline))
        {
            var tampered = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Malware,
                Title = "Gespeicherter sauberer Zustand wurde verändert",
                Description = $"Die Baseline-Datei {BaselineService.FilePath} passt nicht mehr zu ihrer Prüfsumme.",
                Explanation = "Jemand hat die gespeicherte Baseline nachträglich bearbeitet. Malware könnte das tun, um sich selbst als 'bekannt' einzutragen.",
                Recommendation = "Baseline von Ihrer Sicherung (z. B. USB-Stick) vergleichen oder nach einer Neuinstallation neu erstellen.",
            };
            tampered.AddIndicator("BASELINE_TAMPERED", "Baseline-Datei wurde manipuliert", 70);
            ctx.Add(tampered);
        }

        var current = BaselineService.Capture();
        var changes = BaselineService.Compare(baseline, current);
        foreach (var c in changes)
        {
            ctx.ThrowIfCancelled();
            var f = new Finding
            {
                ScannerId = Id,
                Category = c.Category switch
                {
                    BaselineService.CatExclusion => FindingCategory.SecurityConfig,
                    BaselineService.CatAdmin or BaselineService.CatAccount => FindingCategory.Account,
                    BaselineService.CatDriver => FindingCategory.Driver,
                    BaselineService.CatBrowserExt => FindingCategory.Browser,
                    BaselineService.CatRootCert or BaselineService.CatHosts => FindingCategory.Network,
                    _ => FindingCategory.Persistence,
                },
                Title = $"{(c.Kind == ChangeKind.Added ? "Neu" : c.Kind == ChangeKind.Changed ? "Geändert" : "Entfernt")} seit sauberem Zustand: {c.Category} „{Short(c.Key)}“",
                Location = c.Key,
            };
            f.Detail("Seit", baseline.CreatedAt.ToString("g")).Detail("Vorher", c.Before).Detail("Jetzt", c.After).Detail("Kategorie", c.Category);

            if (c.Kind == ChangeKind.Removed)
            {
                f.AddIndicator("BASELINE_REMOVED", $"{c.Category} wurde seit dem {baseline.CreatedAt:d} entfernt", 0);
                f.Description = $"{c.Category} „{c.Key}“ gab es im sauberen Zustand, jetzt nicht mehr (z. B. deinstalliert).";
            }
            else
            {
                int w = Weight.GetValueOrDefault(c.Category, 15);
                f.AddIndicator("NEW_SINCE_BASELINE", $"{c.Category} ist seit dem sauberen Zustand ({baseline.CreatedAt:d}) {(c.Kind == ChangeKind.Added ? "neu" : "verändert")}", w);
                f.Description = $"{c.Category} „{c.Key}“ {(c.Kind == ChangeKind.Added ? "ist neu" : "wurde verändert")}: {c.After}";
                // Zugehoerige Datei mitbewerten (Signatur, Ort, Tarnung)
                var (exe, payload) = PathUtil.ResolveCommandLine(c.After?.Split(" | ").Last());
                if ((payload ?? exe) is { } target && File.Exists(target)) ExecutableAssessor.Assess(f, target, ctx.Trust);
            }
            f.Explanation = "Seit Sie den sauberen Zustand gespeichert haben, hat sich hier etwas verändert. Das ist normal, wenn Sie inzwischen Programme installiert oder aktualisiert haben – " +
                            "aber genau so fallen auch heimliche Einnistungen auf.";
            f.Recommendation = "Kennen Sie die Änderung (Installation, Update)? Dann ist alles in Ordnung. Wenn nicht: Fund genauer prüfen und ggf. entfernen. " +
                               "Nach vielen gewollten Änderungen können Sie den aktuellen Zustand als neuen sauberen Zustand speichern.";
            ctx.Add(f);
        }
        ctx.Note($"{changes.Count} Änderung(en) seit {baseline.CreatedAt:g}.");
        return Task.CompletedTask;
    }

    private static string Short(string key) => key.Length <= 70 ? key : "…" + key[^69..];
}
