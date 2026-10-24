using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ScanMe.Core.Engine;
using ScanMe.Core.Models;
using ScanMe.Core.Scanners;

Console.OutputEncoding = Encoding.UTF8;

var options = new ScanOptions();
string? jsonOut = null;
Severity minSeverity = Severity.Low;
var only = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

for (int i = 0; i < args.Length; i++)
{
    switch (args[i].ToLowerInvariant())
    {
        case "--quick": options.Profile = ScanProfile.Quick; break;
        case "--json" when i + 1 < args.Length: jsonOut = args[++i]; break;
        case "--all": minSeverity = Severity.Info; break;
        case "--no-defender": options.UseDefender = false; break;
        case "--only" when i + 1 < args.Length:
            foreach (var s in args[++i].Split(',')) only.Add(s.Trim());
            break;
        case "--help" or "-h" or "/?":
            Console.WriteLine("""
                scanme-cli – Blue-Team-Scanner fuer Windows

                  --quick            Schnellscan
                  --only a,b         Nur bestimmte Scanner (IDs siehe unten)
                  --all              Auch Info-Funde anzeigen
                  --json <datei>     Ergebnis als JSON speichern
                  --no-defender      Microsoft Defender nicht einbeziehen
                """);
            foreach (var s in ScannerCatalog.CreateAll()) Console.WriteLine($"  {s.Id,-14} {s.Name}");
            return 0;
    }
}

// ---- Maintainer-Werkzeuge fuer signierte Regel-Updates ----
string keyFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".scanme", "rules-signing-key.pem");
if (args.Length > 0 && args[0] == "--rules-keygen")
{
    if (File.Exists(keyFile)) { Console.WriteLine($"Schlüssel existiert bereits: {keyFile} (wird nicht überschrieben)."); return 1; }
    var (priv, pub) = ScanMe.Core.Updates.RuleSigning.GenerateKeyPair();
    Directory.CreateDirectory(Path.GetDirectoryName(keyFile)!);
    File.WriteAllText(keyFile, priv);
    Console.WriteLine($"Privater Schlüssel: {keyFile}\n→ NIEMALS ins Repository legen, sicher sichern (z. B. Passwort-Manager).\n\nÖffentlicher Schlüssel (in RuleSigning.PublicKey eintragen):\n{pub}");
    return 0;
}
if (args.Length > 1 && args[0] == "--rules-sign")
{
    string rulesPath = args[1];
    string pem = File.ReadAllText(args.Length > 2 ? args[2] : keyFile);
    byte[] data = File.ReadAllBytes(rulesPath);
    var set = ScanMe.Core.Updates.RuleStore.Parse(data); // Syntax pruefen, bevor signiert wird
    string sig = ScanMe.Core.Updates.RuleSigning.Sign(data, pem);
    File.WriteAllText(rulesPath + ".sig", sig);
    bool ok = ScanMe.Core.Updates.RuleSigning.Verify(data, sig);
    Console.WriteLine($"Signiert: {rulesPath}.sig (Regelversion {set.Version}, {set.CommandLineRules.Count} Kommandozeilen-, {set.ContentSignatures.Count} Inhaltsregeln)");
    Console.WriteLine(ok ? "✔ Passt zum öffentlichen Schlüssel in ScanMe." : "✖ ACHTUNG: passt NICHT zum eingebauten öffentlichen Schlüssel!");
    return ok ? 0 : 1;
}
if (args.Length > 1 && args[0] == "--rules-verify")
{
    byte[] data = File.ReadAllBytes(args[1]);
    bool ok = File.Exists(args[1] + ".sig") && ScanMe.Core.Updates.RuleSigning.Verify(data, File.ReadAllText(args[1] + ".sig"));
    Console.WriteLine(ok ? "✔ Signatur gültig." : "✖ Signatur ungültig oder fehlt.");
    return ok ? 0 : 1;
}
if (args.Contains("--hardening"))
{
    foreach (var group in ScanMe.Core.Hardening.HardeningCatalog.All.GroupBy(i => i.Group))
    {
        Console.WriteLine($"\n== {group.Key}");
        foreach (var item in group)
        {
            var state = item.Read();
            string rec = item.Recommended is { } r ? $"(empfohlen: {ScanMe.Core.Hardening.HardeningService.Text(r)})" : "(optional)";
            Console.WriteLine($"  [{ScanMe.Core.Hardening.HardeningService.Text(state),-15}] {item.Title} {rec}");
        }
    }
    var hits = ScanMe.Core.Hardening.HardeningService.RecentHits();
    Console.WriteLine($"\nTestmodus-/Blockier-Ereignisse (14 Tage): {hits.Count}");
    foreach (var h in hits.Take(15)) Console.WriteLine($"  {h.When:g} {(h.Blocked ? "BLOCKIERT" : "wäre blockiert")}: {h.Rule} – {h.Process} → {h.Target}");
    return 0;
}
if (args.Contains("--baseline-save"))
{
    var snap = ScanMe.Core.Baseline.BaselineService.Capture();
    ScanMe.Core.Baseline.BaselineService.Save(snap);
    Console.WriteLine($"Sauberer Zustand gespeichert: {ScanMe.Core.Baseline.BaselineService.FilePath}");
    foreach (var c in snap.Categories) Console.WriteLine($"  {c.Key,-22} {c.Value.Count,5} Einträge");
    Console.WriteLine($"Prüfsumme: {snap.Checksum}");
    return 0;
}
if (args.Contains("--baseline-diff"))
{
    var b = ScanMe.Core.Baseline.BaselineService.Load();
    if (b == null) { Console.WriteLine("Kein sauberer Zustand gespeichert (--baseline-save)."); return 1; }
    Console.WriteLine(ScanMe.Core.Baseline.BaselineService.IsIntact(b) ? $"Baseline vom {b.CreatedAt:g} – Prüfsumme ok" : "ACHTUNG: Baseline-Datei wurde verändert!");
    var changes = ScanMe.Core.Baseline.BaselineService.Compare(b, ScanMe.Core.Baseline.BaselineService.Capture());
    foreach (var c in changes) Console.WriteLine($"  [{c.Kind,-7}] {c.Category}: {c.Key} {(c.After != null ? "= " + c.After : "")}");
    Console.WriteLine($"{changes.Count} Änderung(en).");
    return 0;
}
if (args.Contains("--update-rules"))
{
    Console.WriteLine(await ScanMe.Core.Updates.OnlineUpdates.UpdateRulesAsync());
    return 0;
}

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// Echtzeitueberwachung: --monitor [sekunden]
if (args.Contains("--monitor", StringComparer.OrdinalIgnoreCase))
{
    int seconds = args.SkipWhile(a => !a.Equals("--monitor", StringComparison.OrdinalIgnoreCase)).Skip(1).Select(a => int.TryParse(a, out var s) ? s : 0).FirstOrDefault();
    using var monitor = new ScanMe.Core.Monitoring.RealtimeMonitor();
    monitor.Detected += e =>
    {
        if (e.Finding.Severity < minSeverity) return;
        Console.WriteLine($"{e.Time:HH:mm:ss} [{e.Finding.Severity.German(),-8} {e.Finding.Score,3}] {e.Kind}: {e.Finding.Title}");
        foreach (var i in e.Finding.Indicators.Where(i => i.Weight > 0)) Console.WriteLine($"           +{i.Weight,3} {i.Text}");
    };
    monitor.StatusChanged += s => Console.WriteLine("» " + s);
    monitor.Start();
    Console.WriteLine(seconds > 0 ? $"Überwache {seconds} s …" : "Überwache – Strg+C zum Beenden.");
    try { await Task.Delay(seconds > 0 ? TimeSpan.FromSeconds(seconds) : Timeout.InfiniteTimeSpan, cts.Token); } catch (OperationCanceledException) { }
    return 0;
}

var scanners = ScannerCatalog.CreateAll().Where(s => only.Count == 0 || only.Contains(s.Id)).ToList();
var engine = new ScanEngine(scanners);

var progress = new Progress<ScanProgress>(p =>
{
    if (string.IsNullOrEmpty(p.ScannerName)) return;
    string line = $"[{p.ScannerIndex + 1}/{p.ScannerCount}] {p.ScannerName}: {p.Message}";
    line = line.Length > 110 ? line[..110] : line.PadRight(110);
    Console.Error.Write("\r" + line);
});

var report = await engine.RunAsync(options, progress, cts.Token);
Console.Error.WriteLine();

Console.WriteLine($"\n=== ScanMe Bericht – {report.MachineName} – {report.OsVersion} ===");
Console.WriteLine($"Adminrechte: {(report.WasElevated ? "ja" : "NEIN (eingeschränkter Scan)")}   Dauer: {(report.FinishedAt - report.StartedAt):mm\\:ss}");
Console.WriteLine($"Gesundheit: {report.HealthScore}/100   Kritisch {report.Count(Severity.Critical)} · Hoch {report.Count(Severity.High)} · Mittel {report.Count(Severity.Medium)} · Niedrig {report.Count(Severity.Low)} · Info {report.Count(Severity.Info)}\n");

foreach (var f in report.Findings.Where(f => f.Severity >= minSeverity))
{
    Console.ForegroundColor = f.Severity switch
    {
        Severity.Critical => ConsoleColor.Magenta,
        Severity.High => ConsoleColor.Red,
        Severity.Medium => ConsoleColor.Yellow,
        Severity.Low => ConsoleColor.Cyan,
        _ => ConsoleColor.Gray,
    };
    Console.WriteLine($"[{f.Severity.German().ToUpperInvariant(),-8} {f.Score,3}] {f.Category.German()} – {f.Title}{(f.IsProtected ? "  (Windows-Komponente, geschuetzt)" : "")}");
    Console.ResetColor();
    if (!string.IsNullOrEmpty(f.Description)) Console.WriteLine($"    {f.Description}");
    foreach (var ind in f.Indicators.Where(x => x.Weight != 0))
        Console.WriteLine($"      {(ind.Weight > 0 ? "+" : "")}{ind.Weight,3}  {ind.Text}");
    if (!string.IsNullOrEmpty(f.Recommendation)) Console.WriteLine($"    → {f.Recommendation}");
    Console.WriteLine();
}

foreach (var r in report.ScannerResults)
{
    Console.WriteLine($"  {r.ScannerName,-32} {r.Duration.TotalSeconds,6:0.0}s  {r.FindingCount,4} Funde{(r.Error != null ? "  FEHLER: " + r.Error : "")}");
    foreach (var n in r.Notes) Console.WriteLine($"      Hinweis: {n}");
}

if (jsonOut != null)
{
    var json = JsonSerializer.Serialize(report, new JsonSerializerOptions
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    });
    await File.WriteAllTextAsync(jsonOut, json);
    Console.WriteLine($"\nJSON gespeichert: {jsonOut}");
}

return report.Count(Severity.Critical) > 0 ? 2 : report.Count(Severity.High) > 0 ? 1 : 0;
