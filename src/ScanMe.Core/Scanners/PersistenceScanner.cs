using ScanMe.Core.Engine;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Models;
using ScanMe.Core.Trust;
using ScanMe.Core.Util;

namespace ScanMe.Core.Scanners;

/// <summary>
/// Findet alles, was automatisch startet – der wichtigste Ort, an dem sich Malware nach
/// einem Angriff dauerhaft einnistet. Teil 1: gemeinsame Bewertung + Registry-Autostarts.
/// </summary>
public sealed partial class PersistenceScanner : IScanner
{
    public string Id => "persistence";
    public string Name => "Autostart & Persistenz";
    public string Description => "Run-Keys, Autostart-Ordner, geplante Tasks, Dienste, WMI, Winlogon, IFEO, LSA und weitere Einnistungsorte.";
    public bool InQuickScan => true;

    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOnceKey = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string PolicyRunKey = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run";
    private const string ApprovedKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

    public Task ScanAsync(ScanContext ctx)
    {
        ctx.Status("Registry-Autostarts …");
        ScanRunKeys(ctx);
        ctx.ThrowIfCancelled();
        ScanWinlogon(ctx);
        ScanIfeo(ctx);
        ScanDllInjectionPoints(ctx);
        ScanLsa(ctx);
        ScanMiscRegistry(ctx);
        ctx.ThrowIfCancelled();

        ctx.Status("Autostart-Ordner …");
        ScanStartupFolders(ctx);
        ctx.ThrowIfCancelled();

        ctx.Status("Geplante Aufgaben …");
        ScanScheduledTasks(ctx);
        ctx.ThrowIfCancelled();

        ctx.Status("Dienste …");
        ScanServices(ctx);
        ctx.ThrowIfCancelled();

        ctx.Status("WMI-Ereignisabonnements …");
        ScanWmiSubscriptions(ctx);

        ctx.Status("Bedienungshilfen & PowerShell-Profile …");
        ScanAccessibilityBackdoors(ctx);
        ScanPowerShellProfiles(ctx);
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    // Gemeinsame Bewertung
    // ------------------------------------------------------------------

    private sealed record Entry(
        string Kind,
        string Name,
        string Location,
        string? Command,
        int BaseWeight = 0,
        string? BaseReason = null,
        bool ReportThirdParty = true,
        bool? Enabled = null);

    /// <summary>
    /// Bewertet einen Autostart-Eintrag und meldet ihn, wenn er auffaellig ist
    /// oder (bei <see cref="Entry.ReportThirdParty"/>) nicht von Microsoft stammt.
    /// </summary>
    private Finding? Evaluate(ScanContext ctx, Entry e, Action<Finding>? customize = null)
    {
        var (exe, payload) = PathUtil.ResolveCommandLine(e.Command);
        var f = new Finding
        {
            ScannerId = Id,
            Category = FindingCategory.Persistence,
            Title = $"{e.Kind}: {e.Name}",
            Location = e.Location,
        };
        f.Detail("Typ", e.Kind).Detail("Ort", e.Location).Detail("Befehl", e.Command);

        if (e.BaseWeight != 0)
            f.AddIndicator("BASE", e.BaseReason ?? e.Kind, e.BaseWeight);

        FileTrustInfo? info = null;
        if (payload != null)
        {
            info = ExecutableAssessor.Assess(f, payload, ctx.Trust);
            f.Detail("Host-Programm", exe);
            f.AddIndicator("VIA_HOST", $"Wird über {Path.GetFileName(exe)} gestartet (Skript-/DLL-Host)", 10);
        }
        else if (exe != null)
        {
            info = ExecutableAssessor.Assess(f, exe, ctx.Trust);
        }
        else if (e.Command != null)
        {
            f.AddIndicator("UNRESOLVED", "Ausgeführte Datei konnte nicht ermittelt werden", 5);
        }

        foreach (var rule in CommandLineRules.Match(e.Command))
            f.AddIndicator("CMD_" + rule.Id, rule.Text + (rule.Mitre != null ? $" [{rule.Mitre}]" : ""), rule.Weight);

        var pup = info != null ? PupCatalog.Find(Path.GetFileName(info.Path)) : null;
        if (pup != null)
            f.AddIndicator(pup.Kind == PupCatalog.Kind.Pup ? "PUP" : "BLOAT",
                pup.Kind == PupCatalog.Kind.Pup ? $"Potenziell unerwünschtes Programm: {pup.Name}" : $"Unnötiger Autostart: {pup.Name}",
                pup.Kind == PupCatalog.Kind.Pup ? 40 : 10);

        if (e.Enabled == false)
        {
            f.AddIndicator("DISABLED", "Eintrag ist deaktiviert (startet nicht)", -15);
            f.Detail("Status", "deaktiviert");
        }
        else if (e.Enabled == true)
        {
            f.Detail("Status", "aktiv");
        }

        customize?.Invoke(f);

        int score = f.Indicators.Sum(i => i.Weight);
        bool microsoft = info is { IsMicrosoftSigned: true };
        bool report = score >= 15 || pup != null || (e.ReportThirdParty && !microsoft);
        if (!report) return null;

        f.Description = $"Startet automatisch: {e.Command ?? "(kein Befehl)"}" + (info?.Exists == true ? $" – Herausgeber: {info.Publisher}" : "");
        f.Explanation = string.IsNullOrEmpty(f.Explanation) ? ExplainKind(e.Kind) : f.Explanation;
        f.Recommendation = score switch
        {
            >= 35 when microsoft => "Hochgradig verdächtig: Ein Windows-Werkzeug wird mit einem verdächtigen Befehl automatisch gestartet. " +
                                    "Eintrag deaktivieren (die Windows-Datei selbst NICHT löschen) und einen vollständigen Defender-Scan ausführen.",
            >= 60 => "Hochgradig verdächtig. Eintrag deaktivieren, zugehörige Datei in Quarantäne verschieben und einen vollständigen Defender-Scan (am besten Offline-Scan) ausführen.",
            >= 35 => "Prüfen, ob Sie dieses Programm kennen. Datei auf VirusTotal prüfen. Falls unbekannt: Eintrag deaktivieren und Datei in Quarantäne verschieben.",
            >= 15 => "Auffällig, aber nicht eindeutig. Kennen Sie das Programm? Falls nicht benötigt, Autostart deaktivieren.",
            _ when pup != null => pup.Advice,
            _ => "Normales Autostart-Programm. Falls Sie es nicht beim Start brauchen, deaktivieren – das beschleunigt den Systemstart.",
        };
        ctx.Add(f);
        return f;
    }

    private static string ExplainKind(string kind) => kind switch
    {
        "Run-Key" or "RunOnce-Key" => "Programme in den Run-Schlüsseln der Registry starten bei jeder Anmeldung. Das ist der häufigste Einnistungsort für Malware (MITRE T1547.001).",
        "Richtlinien-Run" => "Autostart über Gruppenrichtlinien-Schlüssel – wird von normaler Software selten genutzt, von Malware gern, weil er weniger bekannt ist.",
        "Autostart-Ordner" => "Dateien im Autostart-Ordner starten bei jeder Anmeldung.",
        "Geplante Aufgabe" => "Geplante Aufgaben können Programme zeitgesteuert, beim Start oder bei der Anmeldung ausführen – auch mit Systemrechten (MITRE T1053.005).",
        "Dienst" => "Dienste laufen im Hintergrund, oft mit Systemrechten, und starten noch vor der Anmeldung (MITRE T1543.003).",
        "WMI-Abonnement" => "WMI-Ereignisabonnements führen Befehle bei bestimmten Ereignissen aus, ohne Datei im Autostart. Eine beliebte dateilose Persistenztechnik von APT-Gruppen (MITRE T1546.003).",
        "IFEO-Debugger" => "Über 'Image File Execution Options' wird beim Start eines Programms stattdessen ein anderes ausgeführt. Wird zur Übernahme von Programmen missbraucht (MITRE T1546.012).",
        "Winlogon" => "Winlogon-Einträge werden bei jeder Anmeldung ausgeführt. Abweichungen vom Standard sind ein starkes Malware-Indiz (MITRE T1547.004).",
        "AppInit-DLL" or "AppCert-DLL" => "Diese DLLs werden in nahezu jeden Prozess geladen – klassische Rootkit-Technik (MITRE T1546.010/009).",
        "LSA-Paket" => "LSA-Pakete werden in den Anmeldeprozess (lsass) geladen und sehen Passwörter im Klartext. Fremde Pakete sind ein Hinweis auf Passwortdiebstahl (MITRE T1547.002/005, T1556.002).",
        _ => "Dieser Mechanismus führt Code automatisch aus.",
    };

    /// <summary>StartupApproved: so deaktiviert der Task-Manager Autostarts.</summary>
    private static bool? IsApproved(string hiveRoot, string approvedSub, string valueName)
    {
        if (RegistryUtil.GetValue($@"{hiveRoot}\{ApprovedKey}\{approvedSub}", valueName) is byte[] b && b.Length > 0)
            return (b[0] & 1) == 0;
        return null;
    }

    // ------------------------------------------------------------------
    // Run-Keys
    // ------------------------------------------------------------------

    private void ScanRunKeys(ScanContext ctx)
    {
        var roots = new List<(string Root, string Label)> { ("HKLM", "Alle Benutzer") };
        foreach (var hive in RegistryUtil.LoadedUserHives())
            roots.Add((hive, RegistryUtil.SidToUser(hive[4..])));

        foreach (var (root, label) in roots)
        {
            bool isMachine = root == "HKLM";
            var keys = new List<(string Path, string Kind, string Approved)>
            {
                ($@"{root}\{RunKey}", "Run-Key", "Run"),
                ($@"{root}\{RunOnceKey}", "RunOnce-Key", ""),
                ($@"{root}\{PolicyRunKey}", "Richtlinien-Run", ""),
            };
            if (isMachine)
            {
                keys.Add((@"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Run-Key", "Run32"));
                keys.Add((@"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce-Key", ""));
            }

            foreach (var (path, kind, approved) in keys)
            {
                foreach (var (name, value) in RegistryUtil.Values(path))
                {
                    if (value is not string cmd || string.IsNullOrWhiteSpace(cmd)) continue;
                    bool? enabled = approved.Length > 0 ? IsApproved(root, approved, name) ?? true : true;
                    var f = Evaluate(ctx, new Entry(kind, string.IsNullOrEmpty(name) ? "(Standard)" : name, path, cmd,
                        BaseWeight: kind == "Richtlinien-Run" ? 15 : 0, BaseReason: "Autostart über Richtlinien-Schlüssel", Enabled: enabled));
                    if (f == null) continue;
                    f.Detail("Benutzer", label);
                    if (approved.Length > 0 && enabled != false)
                        f.Actions.Insert(0, new RemediationAction
                        {
                            Kind = RemediationKind.DisableAutostart,
                            Label = "Autostart deaktivieren",
                            Target = $@"{root}\{ApprovedKey}\{approved}",
                            Argument = name,
                        });
                    else if (approved.Length == 0)
                        f.Actions.Insert(0, new RemediationAction
                        {
                            Kind = RemediationKind.DeleteRegistryValue,
                            Label = "Eintrag entfernen (mit Sicherung)",
                            Target = path,
                            Argument = name,
                        });
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Winlogon
    // ------------------------------------------------------------------

    private void ScanWinlogon(ScanContext ctx)
    {
        const string wl = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        string? shell = RegistryUtil.GetString(wl, "Shell");
        if (shell != null && !shell.Trim().Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
            WinlogonFinding(ctx, wl, "Shell", shell, "explorer.exe");

        string? userinit = RegistryUtil.GetString(wl, "Userinit");
        if (userinit != null)
        {
            var parts = userinit.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            bool ok = parts.Length == 1 && Path.GetFileName(Environment.ExpandEnvironmentVariables(parts[0])).Equals("userinit.exe", StringComparison.OrdinalIgnoreCase)
                      && PathUtil.IsInSystemDirectory(PathUtil.Normalize(parts[0]));
            if (!ok) WinlogonFinding(ctx, wl, "Userinit", userinit, Path.Combine(PathUtil.System32, "userinit.exe") + ",");
        }

        foreach (var name in new[] { "Taskman", "AppSetup", "GinaDLL" })
        {
            string? v = RegistryUtil.GetString(wl, name);
            if (!string.IsNullOrWhiteSpace(v)) WinlogonFinding(ctx, wl, name, v, "(nicht gesetzt)");
        }

        // Benutzerspezifische Shell-Ueberschreibung existiert normalerweise nicht.
        foreach (var hive in RegistryUtil.LoadedUserHives())
        {
            string key = $@"{hive}\Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
            string? userShell = RegistryUtil.GetString(key, "Shell");
            if (!string.IsNullOrWhiteSpace(userShell)) WinlogonFinding(ctx, key, "Shell", userShell, "(nicht gesetzt)");
        }
    }

    private void WinlogonFinding(ScanContext ctx, string key, string value, string actual, string expected)
    {
        var f = Evaluate(ctx, new Entry("Winlogon", value, key, actual, 55, $"Winlogon-{value} weicht vom Windows-Standard ab"));
        if (f == null) return;
        f.Detail("Erwartet", expected);
        f.Actions.Insert(0, new RemediationAction
        {
            Kind = RemediationKind.RestoreRegistryValue,
            Label = "Windows-Standard wiederherstellen",
            Target = key,
            Argument = value + "=" + (expected.StartsWith('(') ? "" : expected),
        });
    }

    // ------------------------------------------------------------------
    // Image File Execution Options
    // ------------------------------------------------------------------

    private static readonly HashSet<string> AccessibilityBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe",
    };

    private void ScanIfeo(ScanContext ctx)
    {
        foreach (var root in new[] { @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                                     @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" })
        {
            foreach (var exe in RegistryUtil.SubKeys(root))
            {
                string key = $@"{root}\{exe}";
                string? debugger = RegistryUtil.GetString(key, "Debugger");
                if (!string.IsNullOrWhiteSpace(debugger))
                {
                    bool access = AccessibilityBinaries.Contains(exe);
                    var f = Evaluate(ctx, new Entry("IFEO-Debugger", exe, key, debugger,
                        access ? 85 : 40,
                        access ? $"Bedienungshilfe {exe} wird umgeleitet – Hintertür am Anmeldebildschirm" : $"Start von {exe} wird auf ein anderes Programm umgeleitet"));
                    f?.Actions.Insert(0, new RemediationAction { Kind = RemediationKind.DeleteRegistryValue, Label = "Umleitung entfernen (mit Sicherung)", Target = key, Argument = "Debugger" });
                }

                // GlobalFlag 0x200 + SilentProcessExit\MonitorProcess: startet Programm beim Beenden eines Prozesses
                if (RegistryUtil.GetInt(key, "GlobalFlag") is int gf && (gf & 0x200) != 0)
                {
                    string spe = $@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{exe}";
                    string? monitor = RegistryUtil.GetString(spe, "MonitorProcess");
                    if (!string.IsNullOrWhiteSpace(monitor))
                        Evaluate(ctx, new Entry("IFEO-Debugger", exe + " (SilentProcessExit)", spe, monitor, 50, "Startet heimlich ein Programm, wenn " + exe + " beendet wird"));
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // AppInit / AppCert
    // ------------------------------------------------------------------

    private void ScanDllInjectionPoints(ScanContext ctx)
    {
        foreach (var key in new[] { @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                                    @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" })
        {
            string? dlls = RegistryUtil.GetString(key, "AppInit_DLLs");
            if (string.IsNullOrWhiteSpace(dlls)) continue;
            bool loaded = RegistryUtil.GetInt(key, "LoadAppInit_DLLs") == 1;
            foreach (var dll in dlls.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries))
                Evaluate(ctx, new Entry("AppInit-DLL", Path.GetFileName(dll), key, dll, loaded ? 50 : 20,
                    loaded ? "DLL wird in jeden Prozess mit grafischer Oberfläche geladen" : "AppInit-DLL eingetragen (Laden derzeit deaktiviert)"));
        }

        const string appCert = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls";
        foreach (var (name, value) in RegistryUtil.Values(appCert))
            if (value is string dll && !string.IsNullOrWhiteSpace(dll))
                Evaluate(ctx, new Entry("AppCert-DLL", name, appCert, dll, 55, "DLL wird in jeden Prozess geladen, der neue Prozesse startet"));
    }

    // ------------------------------------------------------------------
    // LSA
    // ------------------------------------------------------------------

    private static readonly HashSet<string> KnownLsaPackages = new(StringComparer.OrdinalIgnoreCase)
    {
        "", "msv1_0", "kerberos", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "negoexts", "livessp",
        "scecli", "rassfm", "msoidssp", "wsauth", "credssp", "negotiate", "\"\"",
    };

    private void ScanLsa(ScanContext ctx)
    {
        foreach (var (key, value) in new[]
        {
            (@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "Authentication Packages"),
            (@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "Notification Packages"),
            (@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "Security Packages"),
            (@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig", "Security Packages"),
        })
        {
            if (RegistryUtil.GetValue(key, value) is not string[] packages) continue;
            foreach (var pkg in packages.Select(p => p.Trim()))
            {
                if (KnownLsaPackages.Contains(pkg)) continue;
                string dll = Path.Combine(PathUtil.System32, pkg.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? pkg : pkg + ".dll");
                Evaluate(ctx, new Entry("LSA-Paket", $"{value}: {pkg}", key, dll, 40, "Unbekanntes Paket im Anmeldeprozess (lsass)"));
            }
        }
    }

    // ------------------------------------------------------------------
    // Weitere Registry-Orte
    // ------------------------------------------------------------------

    private void ScanMiscRegistry(ScanContext ctx)
    {
        // BootExecute – Standard: "autocheck autochk *"
        const string sm = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager";
        if (RegistryUtil.GetValue(sm, "BootExecute") is string[] boot)
        {
            foreach (var entry in boot.Where(b => !string.IsNullOrWhiteSpace(b)))
            {
                if (entry.Trim().Equals("autocheck autochk *", StringComparison.OrdinalIgnoreCase)) continue;
                string first = entry.Trim().Split(' ')[0];
                string exe = Path.Combine(PathUtil.System32, first.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? first : first + ".exe");
                Evaluate(ctx, new Entry("BootExecute", first, sm, exe, 30, "Programm läuft beim Systemstart noch vor Windows"));
            }
        }

        // cmd.exe AutoRun – wird bei jedem Start der Eingabeaufforderung ausgefuehrt
        var cmdKeys = new List<string> { @"HKLM\SOFTWARE\Microsoft\Command Processor", @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Command Processor" };
        cmdKeys.AddRange(RegistryUtil.LoadedUserHives().Select(h => $@"{h}\Software\Microsoft\Command Processor"));
        foreach (var key in cmdKeys)
        {
            string? autorun = RegistryUtil.GetString(key, "AutoRun");
            if (!string.IsNullOrWhiteSpace(autorun))
            {
                var f = Evaluate(ctx, new Entry("cmd-AutoRun", "AutoRun", key, autorun, 35, "Befehl wird bei jedem Start von cmd.exe ausgeführt"));
                f?.Actions.Insert(0, new RemediationAction { Kind = RemediationKind.DeleteRegistryValue, Label = "Eintrag entfernen (mit Sicherung)", Target = key, Argument = "AutoRun" });
            }
        }

        // Netsh-Helper-DLLs
        const string netsh = @"HKLM\SOFTWARE\Microsoft\NetSh";
        foreach (var (name, value) in RegistryUtil.Values(netsh))
        {
            if (value is not string dll || string.IsNullOrWhiteSpace(dll)) continue;
            string path = Path.IsPathRooted(dll) ? dll : Path.Combine(PathUtil.System32, dll);
            Evaluate(ctx, new Entry("Netsh-Helper", name, netsh, path, 15, "DLL wird bei jedem Aufruf von netsh geladen", ReportThirdParty: true));
        }

        ScanRunDialogHistory(ctx);
    }

    /// <summary>
    /// ClickFix: Eine gefaelschte "Ich bin kein Roboter"-Seite kopiert einen Befehl in die Zwischenablage und
    /// fordert auf, Win+R, Strg+V, Enter zu druecken. Der Befehl bleibt im Verlauf des Ausfuehren-Dialogs (RunMRU).
    /// </summary>
    private void ScanRunDialogHistory(ScanContext ctx)
    {
        foreach (var hive in RegistryUtil.LoadedUserHives())
        {
            string key = $@"{hive}\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";
            foreach (var (name, value) in RegistryUtil.Values(key))
            {
                if (name.Equals("MRUList", StringComparison.OrdinalIgnoreCase) || value is not string entry) continue;
                string command = entry.EndsWith(@"\1", StringComparison.Ordinal) ? entry[..^2] : entry;
                var rules = CommandLineRules.Match(command).ToList();
                if (rules.Count == 0) continue;

                var f = new Finding
                {
                    ScannerId = Id,
                    Category = FindingCategory.Malware,
                    Title = "Verdächtiger Befehl im Ausführen-Dialog (Win+R)",
                    Location = key,
                    Description = $"Im Verlauf des Ausführen-Dialogs steht: {TextUtil.Truncate(command, 300)}",
                    Explanation = "Bei der 'ClickFix'-Masche zeigt eine Webseite ein gefälschtes Captcha und fordert auf, Win+R zu drücken, " +
                                  "einen (heimlich kopierten) Befehl einzufügen und Enter zu drücken. Dadurch wird Schadsoftware – meist ein Passwortdieb – installiert.",
                    Recommendation = "Wenn Sie diesen Befehl nicht selbst eingegeben haben: vollständigen Scan durchführen, Passwörter von einem anderen Gerät aus ändern " +
                                     "und alle Sitzungen abmelden. Den Verlaufseintrag können Sie danach entfernen.",
                };
                f.AddIndicator("RUNMRU", "Befehl wurde manuell über Win+R ausgeführt", 15);
                foreach (var r in rules) f.AddIndicator("CMD_" + r.Id, r.Text + (r.Mitre != null ? $" [{r.Mitre}]" : ""), r.Weight);
                f.Detail("Benutzer", RegistryUtil.SidToUser(hive[4..])).Detail("Befehl", command);
                f.Actions.Add(new RemediationAction { Kind = RemediationKind.DeleteRegistryValue, Label = "Verlaufseintrag entfernen", Target = key, Argument = name });
                ctx.Add(f);
            }
        }
    }
}
