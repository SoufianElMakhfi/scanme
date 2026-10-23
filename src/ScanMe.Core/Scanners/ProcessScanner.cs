using ScanMe.Core.Engine;
using ScanMe.Core.Inventory;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Models;
using ScanMe.Core.Util;

namespace ScanMe.Core.Scanners;

/// <summary>
/// Analysiert alle laufenden Prozesse: versteckte Prozesse, Tarnung als Systemprozess,
/// verdaechtige Eltern-Kind-Ketten, boesartige Kommandozeilen, Ressourcenfresser und Bloat.
/// </summary>
public sealed class ProcessScanner : IScanner
{
    public const string SnapshotKey = "processes";

    public string Id => "processes";
    public string Name => "Laufende Prozesse";
    public string Description => "Versteckte, getarnte und verdaechtige Prozesse sowie unnoetige Hintergrundprogramme.";
    public bool InQuickScan => true;

    /// <summary>Programme, die Dokumente/Mails oeffnen – starten sie Shells, ist das ein Phishing-Indiz.</summary>
    private static readonly HashSet<string> DocumentApps = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe", "visio.exe",
        "acrord32.exe", "acrobat.exe", "foxitreader.exe", "foxitpdfreader.exe", "sumatrapdf.exe",
        "thunderbird.exe", "olk.exe", "hxoutlook.exe", "wordpad.exe", "hwp.exe",
    };

    private static readonly HashSet<string> Browsers = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "iexplore.exe",
    };

    private static readonly HashSet<string> Shells = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
        "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "msiexec.exe", "schtasks.exe", "hh.exe",
    };

    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "wscript.exe", "cscript.exe", "mshta.exe",
    };

    public static ProcessSnapshot GetSnapshot(ScanContext ctx) =>
        ctx.Shared(SnapshotKey, () => ProcessSnapshot.Capture());

    public Task ScanAsync(ScanContext ctx)
    {
        ctx.Status("Erfasse Prozessliste aus mehreren Quellen …");
        var snap = GetSnapshot(ctx);
        if (!ctx.IsElevated)
            ctx.Note("Ohne Adminrechte sind Pfade und Kommandozeilen fremder Prozesse teilweise nicht lesbar.");

        ReportHidden(ctx, snap);

        var instanceCounts = snap.Processes.Values
            .GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        // Mehrere Instanzen desselben Programms mit gleichem Befund werden zu einem Fund zusammengefasst.
        var groups = new Dictionary<string, Finding>(StringComparer.OrdinalIgnoreCase);
        int i = 0;
        foreach (var p in snap.Processes.Values.OrderBy(p => p.Pid))
        {
            ctx.ThrowIfCancelled();
            if (++i % 20 == 0) ctx.Status($"Pruefe Prozess {i}/{snap.Processes.Count}: {p.Name}");
            if (SystemProcesses.IsKernelPseudoProcess(p.Name, p.Pid)) continue;

            var f = AnalyzeProcess(ctx, snap, p, instanceCounts);
            if (f == null) continue;

            string key = (p.ImagePath ?? p.Name) + "|" + string.Join(",", f.Indicators.Select(x => x.Code).Order());
            if (groups.TryGetValue(key, out var existing))
                MergeInstance(existing, p);
            else
                groups[key] = f;
        }
        foreach (var f in groups.Values) ctx.Add(f);

        ReportResourceHogs(ctx, snap);
        return Task.CompletedTask;
    }

    private void ReportHidden(ScanContext ctx, ProcessSnapshot snap)
    {
        foreach (var (pid, path) in snap.HiddenCandidates)
        {
            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Process,
                Title = $"Versteckter Prozess (PID {pid})",
                ProcessId = pid,
                Description = $"Der Prozess mit PID {pid} laeuft, taucht aber nicht in der normalen Prozessliste von Windows auf." +
                              (path != null ? $" Datei: {path}" : ""),
                Explanation = "Wenn ein Prozess direkt ansprechbar ist, aber in der Prozessliste fehlt, versteckt ihn vermutlich ein Rootkit. " +
                              "Genau so bleiben Schadprogramme im Task-Manager unsichtbar.",
                Recommendation = "Den PC mit einem Offline-Scanner pruefen (Microsoft Defender Offline-Scan, startet ausserhalb von Windows). " +
                                 "Bei Bestaetigung: wichtige Daten sichern und Windows neu installieren.",
            };
            f.AddIndicator("HIDDEN_PROCESS", "Prozess ist vor der Windows-Prozessliste versteckt", 85);
            if (path != null) ExecutableAssessor.Assess(f, path, ctx.Trust);
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.KillProcess, Label = "Prozess beenden", Target = pid.ToString() });
            ctx.Add(f);
        }

        // Prozesse, die die Kernel-Liste kennt, WMI aber nicht (WMI-Manipulation / Hooking)
        bool wmiWorked = snap.Processes.Values.Any(p => p.SeenBy.Contains(ProcessSnapshot.SrcWmi));
        if (!wmiWorked) return;
        foreach (var p in snap.Processes.Values)
        {
            if (p.SeenBy.Contains(ProcessSnapshot.SrcWmi) || SystemProcesses.IsKernelPseudoProcess(p.Name, p.Pid)) continue;
            if (p.StartTime is { } st && (DateTime.Now - st).TotalSeconds < 10) continue; // gerade erst gestartet
            if (p.Name.Equals("Secure System", StringComparison.OrdinalIgnoreCase)) continue;

            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Process,
                Title = $"Prozess vor WMI verborgen: {p.Name}",
                ProcessId = p.Pid,
                Description = $"{p.Name} (PID {p.Pid}) ist im Kernel sichtbar, wird aber von WMI nicht gemeldet.",
                Explanation = "Abweichungen zwischen verschiedenen Prozesslisten koennen auf Manipulation hinweisen, aber auch auf sehr kurzlebige Prozesse.",
                Recommendation = "Scan wiederholen. Tritt der Fund erneut auf, Prozess genauer pruefen.",
            };
            f.AddIndicator("WMI_MISMATCH", "Prozess fehlt in der WMI-Prozessliste", 30);
            if (p.ImagePath != null) ExecutableAssessor.Assess(f, p.ImagePath, ctx.Trust);
            ctx.Add(f);
        }
    }

    private static void MergeInstance(Finding f, ProcessEntry p)
    {
        f.Details["PID"] = f.Details["PID"] + ", " + p.Pid;
        int idx = f.Actions.FindIndex(a => a.Kind == RemediationKind.KillProcess);
        if (idx >= 0)
        {
            var old = f.Actions[idx];
            f.Actions[idx] = new RemediationAction { Kind = old.Kind, Label = "Alle Instanzen beenden", Target = old.Target + "," + p.Pid };
        }
    }

    private Finding? AnalyzeProcess(ScanContext ctx, ProcessSnapshot snap, ProcessEntry p, Dictionary<string, int> instanceCounts)
    {
        var f = new Finding
        {
            ScannerId = Id,
            Category = FindingCategory.Process,
            Title = p.Name,
            ProcessId = p.Pid,
        };

        var parent = snap.Get(p.ParentPid);
        // PID-Wiederverwendung: Der "Elternprozess" muss vor dem Kind gestartet sein.
        if (parent != null && parent.StartTime != null && p.StartTime != null && parent.StartTime > p.StartTime) parent = null;

        f.Detail("PID", p.Pid.ToString())
         .Detail("Elternprozess", parent != null ? $"{parent.Name} (PID {parent.Pid})" : $"beendet (PID {p.ParentPid})")
         .Detail("Kommandozeile", p.CommandLine)
         .Detail("Gestartet", p.StartTime?.ToString("g"))
         .Detail("Sitzung", p.IsService ? "0 (Dienst / Hintergrund)" : p.SessionId.ToString())
         .Detail("Arbeitsspeicher", TextUtil.FormatBytes(p.WorkingSet))
         .Detail("CPU", $"{p.CpuPercent:0.0} %")
         .Detail("Sichtbares Fenster", p.HasVisibleWindow ? "ja" : "nein");

        var info = p.ImagePath != null ? ExecutableAssessor.Assess(f, p.ImagePath, ctx.Trust, addActions: true) : null;
        if (info == null && !ctx.IsElevated) return null; // ohne Pfad und ohne Rechte keine sinnvolle Bewertung

        var profile = SystemProcesses.Get(p.Name);

        // --- Datei geloescht, Prozess laeuft ---
        if (p.ImagePath != null && info is { Exists: false })
        {
            f.Indicators.RemoveAll(x => x.Code == "FILE_MISSING");
            f.AddIndicator("IMAGE_DELETED", "Die Programmdatei wurde geloescht, waehrend der Prozess weiterlaeuft (typisch fuer Malware)", 50);
        }

        // --- Elternprozess-Pruefung fuer Systemprozesse ---
        if (profile != null && profile.ExpectedParents.Length > 0 && parent != null
            && !profile.ExpectedParents.Contains(parent.Name, StringComparer.OrdinalIgnoreCase))
        {
            f.AddIndicator("BAD_PARENT", $"{p.Name} wurde von \"{parent.Name}\" gestartet – erwartet: {string.Join(", ", profile.ExpectedParents)}", 45);
        }

        // --- Mehrfachinstanzen ---
        if (profile is { SingleInstance: true } && instanceCounts.TryGetValue(p.Name, out int count) && count > 1)
            f.AddIndicator("MULTI_INSTANCE", $"{count} Instanzen von {p.Name} – normalerweise gibt es nur eine", 55);

        // --- Phishing-Kette: Office/PDF/Mail startet Shell ---
        if (parent != null && Shells.Contains(p.Name))
        {
            if (DocumentApps.Contains(parent.Name))
                f.AddIndicator("DOC_SPAWN", $"{parent.Name} hat {p.Name} gestartet – typisch fuer boesartige Makros/Phishing-Anhaenge", 65);
            else if (Browsers.Contains(parent.Name))
            {
                // Native-Messaging-Hosts von Erweiterungen werden vom Browser ueber cmd.exe gestartet.
                bool nativeMessaging = p.CommandLine?.Contains("chrome-extension://", StringComparison.OrdinalIgnoreCase) == true
                                       || p.CommandLine?.Contains("moz-extension://", StringComparison.OrdinalIgnoreCase) == true;
                if (nativeMessaging)
                    f.AddIndicator("BROWSER_NATIVE_HOST", $"Native-Messaging-Host einer Browsererweiterung (von {parent.Name} gestartet)", 5);
                else
                    f.AddIndicator("BROWSER_SPAWN", $"Browser {parent.Name} hat {p.Name} gestartet", 40);
            }
        }

        // --- Skript-Hosts ---
        if (ScriptHosts.Contains(p.Name))
            f.AddIndicator("SCRIPT_HOST", $"Skript-Host {p.Name} laeuft – wird selten legitim dauerhaft genutzt", 15);

        // --- Kommandozeile ---
        foreach (var rule in CommandLineRules.Match(p.CommandLine))
            f.AddIndicator("CMD_" + rule.Id, rule.Text + (rule.Mitre != null ? $" [{rule.Mitre}]" : ""), rule.Weight);

        // --- Unsichtbar im Hintergrund aus Benutzerordner ---
        var loc = LocationClassifier.Classify(p.ImagePath);
        if (!p.HasVisibleWindow && LocationClassifier.IsUserWritable(loc) && info?.Signature != Trust.SignatureState.Valid)
            f.AddIndicator("HIDDEN_BACKGROUND", "Laeuft unsichtbar im Hintergrund (kein Fenster) aus einem Benutzerordner", 10);

        // --- Bloat / PUP ---
        var pup = PupCatalog.Find(p.Name);
        if (pup != null)
        {
            f.AddIndicator(pup.Kind == PupCatalog.Kind.Pup ? "PUP" : "BLOAT",
                pup.Kind == PupCatalog.Kind.Pup ? $"Potenziell unerwuenschtes Programm: {pup.Name}" : $"Unnoetiger Hintergrundprozess: {pup.Name}",
                pup.Kind == PupCatalog.Kind.Pup ? 40 : 15);
        }

        int total = f.Indicators.Sum(x => x.Weight);
        if (total < 15 && pup == null) return null; // unauffaellig

        // --- Texte zusammenstellen ---
        var tool = KnownTools.FindByProcessName(p.Name);
        bool critical = SystemProcesses.IsNeverKill(p.Name) && f.IsProtected;

        f.Description = BuildDescription(p, info?.Publisher);
        f.Explanation = pup != null && f.Indicators.All(x => x.Code is "BLOAT" or "PUP" || x.Weight <= 0)
            ? pup.Advice
            : tool != null
                ? $"{tool.Name} ist {KnownTools.KindText(tool.Kind)}. {tool.Note}"
                : profile != null && !f.IsProtected
                    ? $"Der echte {profile.Name}: {profile.Description} Abweichungen bei Pfad, Signatur oder Elternprozess sind ein starkes Indiz fuer Tarnung."
                    : "Die Bewertung ergibt sich aus den aufgefuehrten Indikatoren.";
        f.Recommendation = BuildRecommendation(f, pup, tool, critical);

        if (!critical && !f.IsProtected)
            f.Actions.Insert(0, new RemediationAction { Kind = RemediationKind.KillProcess, Label = "Prozess beenden", Target = p.Pid.ToString() });

        return f;
    }

    private static string BuildDescription(ProcessEntry p, string? publisher)
    {
        var parts = new List<string> { $"{p.Name} laeuft seit {p.StartTime:g}" };
        if (p.ImagePath != null) parts.Add($"aus \"{p.ImagePath}\"");
        if (publisher != null) parts.Add($"Herausgeber: {publisher}");
        if (!p.HasVisibleWindow) parts.Add("ohne sichtbares Fenster");
        return string.Join(", ", parts) + ".";
    }

    private static string BuildRecommendation(Finding f, PupCatalog.Entry? pup, KnownTools.Tool? tool, bool critical)
    {
        int score = f.Indicators.Sum(x => x.Weight);
        if (critical)
            return "Kritischer Windows-Prozess – nicht beenden. Falls die Kommandozeile verdaechtig ist, den Ursprung (Autostart, Task) untersuchen.";
        if (pup is { Kind: PupCatalog.Kind.Bloat } && score < 35)
            return pup.Advice + " Autostart im Task-Manager → Autostart-Apps deaktivieren.";
        if (pup is { Kind: PupCatalog.Kind.Pup })
            return pup.Advice + " Ueber Einstellungen → Apps → Installierte Apps entfernen.";
        if (tool is { Kind: KnownTools.ToolKind.RemoteAccess })
            return "Haben Sie dieses Programm selbst installiert und nutzen es? Falls nicht – oder falls jemand Sie am Telefon dazu aufgefordert hat – " +
                   "Programm sofort beenden, deinstallieren, Internet trennen und Passwoerter (insb. Online-Banking) von einem anderen Geraet aus aendern.";
        if (score >= 60)
            return "Prozess beenden, Datei in Quarantaene verschieben und den Autostart-Eintrag dazu entfernen. Anschliessend vollstaendigen Defender-Scan ausfuehren " +
                   "und die Datei auf VirusTotal pruefen.";
        if (score >= 35)
            return "Pruefen, ob Sie das Programm kennen. Datei auf VirusTotal pruefen. Unbekannt? Prozess beenden und Datei in Quarantaene verschieben.";
        return "Wahrscheinlich harmlos, aber auffaellig. Pruefen, ob Sie das Programm kennen und brauchen.";
    }

    private void ReportResourceHogs(ScanContext ctx, ProcessSnapshot snap)
    {
        long totalRam = GetTotalRam();
        foreach (var p in snap.Processes.Values)
        {
            if (SystemProcesses.IsKernelPseudoProcess(p.Name, p.Pid)) continue;
            bool cpu = p.CpuPercent >= 25;
            bool ram = totalRam > 0 && p.WorkingSet > totalRam * 0.25;
            if (!cpu && !ram) continue;

            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Compatibility,
                Title = $"Hohe Systemlast: {p.Name}",
                ProcessId = p.Pid,
                Description = $"{p.Name} (PID {p.Pid}) verbraucht {p.CpuPercent:0} % CPU und {TextUtil.FormatBytes(p.WorkingSet)} Arbeitsspeicher.",
                Explanation = "Dauerhaft hohe Last bremst den PC. Unbekannte Prozesse mit hoher CPU-Last koennen heimliche Krypto-Miner sein.",
                Recommendation = "Pruefen, ob gerade eine Aufgabe laeuft (Update, Spiel, Rendering). Falls nicht und das Programm unbekannt ist: genauer untersuchen.",
            };
            f.AddIndicator("RESOURCE", cpu ? "Hohe CPU-Auslastung" : "Hoher Speicherverbrauch", 15);
            if (p.ImagePath != null)
            {
                var info = ctx.Trust.Get(p.ImagePath);
                ExecutableAssessor.AddDetails(f, info);
                if (info.IsWindowsComponent) f.IsProtected = true;
                if (cpu && info.Signature != Trust.SignatureState.Valid)
                    f.AddIndicator("MINER_SUSPECT", "Unsignierter Prozess mit hoher CPU-Last (moeglicher Krypto-Miner)", 25);
            }
            ctx.Add(f);
        }
    }

    private static long GetTotalRam()
    {
        try { return (long)GC.GetGCMemoryInfo().TotalAvailableMemoryBytes; }
        catch { return 0; }
    }
}
