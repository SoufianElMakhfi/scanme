using System.Diagnostics;
using System.Management;
using Microsoft.Win32;
using ScanMe.Core.Models;
using ScanMe.Core.Scanners;
using ScanMe.Core.Util;

namespace ScanMe.Core.Actions;

public sealed record ActionResult(bool Success, string Message)
{
    public static ActionResult Ok(string m) => new(true, m);
    public static ActionResult Fail(string m) => new(false, m);
}

/// <summary>Fuehrt Gegenmassnahmen aus – jede mit Sicherheitspruefung und (wo moeglich) Rueckgaengig-Eintrag.</summary>
public static class ActionExecutor
{
    public static Task<ActionResult> ExecuteAsync(Finding finding, RemediationAction action) => Task.Run(() =>
    {
        try
        {
            return action.Kind switch
            {
                RemediationKind.KillProcess => KillProcesses(action.Target),
                RemediationKind.QuarantineFile => Quarantine.Add(action.Target!, finding.Title),
                RemediationKind.DisableAutostart => DisableAutostart(action.Target!, action.Argument!),
                RemediationKind.DeleteRegistryValue => DeleteRegistryValue(action.Target!, action.Argument!),
                RemediationKind.RestoreRegistryValue => SetRegistryValue(action.Target!, action.Argument!),
                RemediationKind.DisableScheduledTask => DisableTask(action.Target!),
                RemediationKind.DisableService => DisableService(action.Target!),
                RemediationKind.RemoveWmiSubscription => RemoveWmi(action.Target!, action.Argument),
                RemediationKind.RemoveDefenderExclusion => RemoveExclusion(action.Target!, action.Argument!),
                RemediationKind.RestoreHostsFile => RestoreHosts(action.Target!),
                RemediationKind.DefenderScanFile => DefenderScan(finding, action.Target!),
                RemediationKind.OpenLocation => OpenLocation(action.Target!),
                RemediationKind.LookupOnline => LookupOnline(action.Target!),
                _ => ActionResult.Fail("Unbekannte Aktion."),
            };
        }
        catch (UnauthorizedAccessException)
        {
            return ActionResult.Fail("Zugriff verweigert – ScanMe muss als Administrator laufen.");
        }
        catch (Exception ex)
        {
            return ActionResult.Fail(ex.Message);
        }
    });

    // ------------------------------------------------------------------

    private static ActionResult KillProcesses(string? targets)
    {
        var pids = (targets ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries).Select(s => int.TryParse(s, out var p) ? p : -1).Where(p => p > 0).ToList();
        var messages = new List<string>();
        int killed = 0;
        foreach (var pid in pids)
        {
            string? block = SafetyGuard.CheckProcess(pid);
            if (block != null) { messages.Add($"PID {pid}: {block}"); continue; }
            try
            {
                using var p = Process.GetProcessById(pid);
                p.Kill();
                p.WaitForExit(3000);
                killed++;
            }
            catch (Exception ex) { messages.Add($"PID {pid}: {ex.Message}"); }
        }
        return killed > 0
            ? ActionResult.Ok($"{killed} Prozess(e) beendet." + (messages.Count > 0 ? " " + string.Join(" ", messages) : ""))
            : ActionResult.Fail(messages.Count > 0 ? string.Join(" ", messages) : "Kein Prozess beendet.");
    }

    /// <summary>Deaktiviert wie der Task-Manager ueber StartupApproved (voll reversibel, Eintrag bleibt erhalten).</summary>
    private static ActionResult DisableAutostart(string approvedKey, string valueName)
    {
        UndoJournal.BackupRegistryValue(approvedKey, valueName, $"Autostart '{valueName}' deaktiviert");
        var (root, sub) = RegistryUtil.Split(approvedKey);
        using var k = root!.CreateSubKey(sub, true);
        var data = new byte[12];
        data[0] = 0x03; // ungerade = deaktiviert
        BitConverter.GetBytes(DateTime.Now.ToFileTime()).CopyTo(data, 4);
        k.SetValue(valueName, data, RegistryValueKind.Binary);
        return ActionResult.Ok($"Autostart '{valueName}' deaktiviert (wie im Task-Manager; rückgängig machbar).");
    }

    private static ActionResult DeleteRegistryValue(string key, string name)
    {
        string? block = SafetyGuard.CheckRegistryDelete(key, name);
        if (block != null) return ActionResult.Fail(block);
        using (var test = RegistryUtil.Open(key))
            if (test == null || !test.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase))
                return ActionResult.Fail("Wert existiert nicht (mehr).");

        UndoJournal.BackupRegistryValue(key, name, $"Registry-Wert '{name}' entfernt ({key})");
        using var k = RegistryUtil.Open(key, writable: true) ?? throw new UnauthorizedAccessException();
        k.DeleteValue(name, false);
        return ActionResult.Ok($"Registry-Wert '{name}' entfernt. Sicherung im Rückgängig-Verlauf.");
    }

    /// <summary>Argument "Name=Wert": setzt einen Registry-Wert gezielt (z. B. Windows-Standard wiederherstellen).</summary>
    private static ActionResult SetRegistryValue(string key, string assignment)
    {
        int eq = assignment.IndexOf('=');
        if (eq <= 0) return ActionResult.Fail("Ungültige Zuweisung.");
        string name = assignment[..eq];
        string value = assignment[(eq + 1)..];

        UndoJournal.BackupRegistryValue(key, name, $"Registry-Wert '{name}' auf '{value}' gesetzt ({key})");
        var (root, sub) = RegistryUtil.Split(key);
        using var k = root!.CreateSubKey(sub, true);
        var existingKind = k.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase) ? k.GetValueKind(name) : (RegistryValueKind?)null;
        if (value.Length == 0 && existingKind != RegistryValueKind.String)
            k.DeleteValue(name, false);
        else if (existingKind is RegistryValueKind.DWord || (existingKind == null && int.TryParse(value, out _)))
            k.SetValue(name, int.Parse(value), RegistryValueKind.DWord);
        else
            k.SetValue(name, value, existingKind ?? RegistryValueKind.String);
        return ActionResult.Ok($"'{name}' gesetzt. Rückgängig machbar.");
    }

    private static ActionResult DisableTask(string taskPath)
    {
        var (code, output) = RunTool("schtasks.exe", $"/Change /TN \"{taskPath}\" /DISABLE");
        if (code != 0) return ActionResult.Fail("Aufgabe konnte nicht deaktiviert werden: " + output.Trim());
        UndoJournal.Add(new UndoEntry { Kind = UndoKind.TaskEnable, Target = taskPath, Description = $"Geplante Aufgabe '{taskPath}' deaktiviert" });
        return ActionResult.Ok("Aufgabe deaktiviert (nicht gelöscht – rückgängig machbar).");
    }

    private static ActionResult DisableService(string name)
    {
        string? block = SafetyGuard.CheckService(name);
        if (block != null) return ActionResult.Fail(block);
        string key = $@"HKLM\SYSTEM\CurrentControlSet\Services\{name}";
        int? previous = RegistryUtil.GetInt(key, "Start");
        if (previous == null) return ActionResult.Fail("Dienst nicht gefunden.");

        RunTool("sc.exe", $"stop \"{name}\"");
        using (var k = RegistryUtil.Open(key, writable: true) ?? throw new UnauthorizedAccessException())
            k.SetValue("Start", 4, RegistryValueKind.DWord);
        UndoJournal.Add(new UndoEntry { Kind = UndoKind.ServiceStart, Target = name, PreviousValue = previous.ToString(), Description = $"Dienst '{name}' deaktiviert" });
        return ActionResult.Ok($"Dienst '{name}' gestoppt und deaktiviert. Rückgängig machbar.");
    }

    private static ActionResult RemoveWmi(string consumerPath, string? filterName)
    {
        var scope = new ManagementScope(@"\\.\root\subscription");
        scope.Connect();
        int removed = 0;
        using (var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding")))
            foreach (ManagementObject b in s.Get())
                using (b)
                    if ((b["Consumer"]?.ToString() ?? "").Contains(consumerPath.Split('.')[1], StringComparison.OrdinalIgnoreCase)) { b.Delete(); removed++; }

        using (var consumer = new ManagementObject(scope, new ManagementPath(consumerPath), null)) { consumer.Delete(); removed++; }
        if (!string.IsNullOrEmpty(filterName))
        {
            try
            {
                using var filter = new ManagementObject(scope, new ManagementPath($"__EventFilter.Name=\"{filterName}\""), null);
                filter.Delete();
                removed++;
            }
            catch { }
        }
        return ActionResult.Ok($"WMI-Abonnement entfernt ({removed} Objekte). Hinweis: nicht rückgängig machbar.");
    }

    private static ActionResult RemoveExclusion(string value, string parameter)
    {
        // Direkt ueber die Defender-WMI-Schnittstelle statt PowerShell: kein Skriptblock-Protokoll, das
        // spaeter faelschlich als "verdaechtiges Skript" erscheint, und keine Kommandozeilen-Quoting-Probleme.
        string? error = InvokeMpPreference("Remove", parameter, value);
        if (error != null) return ActionResult.Fail("Ausnahme konnte nicht entfernt werden (Manipulationsschutz aktiv?): " + error);
        if (ExclusionExists(parameter, value))
            return ActionResult.Fail("Defender hat die Ausnahme nicht entfernt (evtl. per Gruppenrichtlinie gesetzt oder Manipulationsschutz aktiv).");
        UndoJournal.Add(new UndoEntry { Kind = UndoKind.DefenderExclusion, Target = value, Name = parameter, Description = $"Defender-Ausnahme '{value}' entfernt" });
        return ActionResult.Ok("Defender-Ausnahme entfernt und überprüft.");
    }

    /// <summary>Ruft MSFT_MpPreference.Add/Remove auf. Rueckgabe: Fehlermeldung oder null.</summary>
    internal static string? InvokeMpPreference(string method, string parameter, string value)
    {
        try
        {
            using var cls = new ManagementClass(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null);
            using var input = cls.GetMethodParameters(method);
            input[parameter] = new[] { value };
            using var output = cls.InvokeMethod(method, input, null);
            uint rc = output?["ReturnValue"] is { } r ? Convert.ToUInt32(r) : 0;
            return rc == 0 ? null : $"Fehlercode {rc}";
        }
        catch (ManagementException ex) { return ex.Message; }
        catch (UnauthorizedAccessException) { return "Zugriff verweigert – Adminrechte erforderlich."; }
    }

    private static bool ExclusionExists(string parameter, string value)
    {
        string sub = parameter switch
        {
            "ExclusionPath" => "Paths",
            "ExclusionExtension" => "Extensions",
            "ExclusionProcess" => "Processes",
            _ => "IpAddresses",
        };
        return RegistryUtil.Values($@"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\{sub}")
            .Any(v => v.Name.Equals(value, StringComparison.OrdinalIgnoreCase));
    }

    private const string DefaultHosts =
        "# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n#\r\n" +
        "# localhost name resolution is handled within DNS itself.\r\n#\t127.0.0.1       localhost\r\n#\t::1             localhost\r\n";

    private static ActionResult RestoreHosts(string hostsPath)
    {
        string backup = Path.Combine(AppPaths.BackupDir, $"hosts_{DateTime.Now:yyyyMMdd_HHmmss}.bak");
        File.Copy(hostsPath, backup, overwrite: true);
        var attrs = File.GetAttributes(hostsPath);
        File.SetAttributes(hostsPath, FileAttributes.Normal);
        File.WriteAllText(hostsPath, DefaultHosts);
        File.SetAttributes(hostsPath, attrs & ~FileAttributes.ReadOnly);
        RunTool("ipconfig.exe", "/flushdns");
        UndoJournal.Add(new UndoEntry { Kind = UndoKind.HostsFile, Target = hostsPath, PreviousValue = backup, Description = "Hosts-Datei auf Standard zurückgesetzt" });
        return ActionResult.Ok($"Hosts-Datei zurückgesetzt. Sicherung: {backup}");
    }

    /// <summary>Haelt das Ergebnis auch am Fund fest, damit "Wie sicher ist das?" sofort stimmt.</summary>
    private static ActionResult DefenderScan(Finding finding, string path)
    {
        var r = Antivirus.DefenderCli.Scan(path, TimeSpan.FromMinutes(30));
        if (r == null) return ActionResult.Fail("Microsoft Defender ist auf diesem PC nicht vorhanden.");
        if (r.TimedOut) return ActionResult.Fail("Microsoft Defender hat nach 30 Minuten nicht geantwortet – Prüfung abgebrochen.");
        if (!r.Completed)
            return ActionResult.Fail($"Microsoft Defender konnte die Datei nicht prüfen (Code 0x{r.FailedHr ?? r.ExitCode:X8}) – vermutlich ist ein anderer Virenschutz aktiv.");
        if (r.Threat is { } threat)
        {
            bool pua = Antivirus.DefenderCli.IsPuaName(threat);
            finding.Checked(Check.Detection(Check.Defender, threat, pua));
            finding.AddIndicator("DEFENDER_DETECTED", $"Microsoft Defender erkennt: {threat}", pua ? 45 : 90);
            return ActionResult.Ok($"Microsoft Defender erkennt: {threat}");
        }
        finding.Checked(Check.Defender, CheckResult.Good, "hat die Datei geprüft: keine Bedrohung erkannt");
        return ActionResult.Ok("Microsoft Defender hat die Datei geprüft und keine Bedrohung erkannt.");
    }

    private static ActionResult OpenLocation(string path)
    {
        if (File.Exists(path))
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        else if (Directory.Exists(path))
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true });
        else
            return ActionResult.Fail("Pfad existiert nicht.");
        return ActionResult.Ok("Explorer geöffnet.");
    }

    private static ActionResult LookupOnline(string sha256)
    {
        // Es wird nur der Hash nachgeschlagen – die Datei selbst wird NICHT hochgeladen.
        Process.Start(new ProcessStartInfo($"https://www.virustotal.com/gui/file/{sha256}") { UseShellExecute = true });
        return ActionResult.Ok("VirusTotal im Browser geöffnet (nur der Hash wird übertragen, nicht die Datei).");
    }

    internal static (int ExitCode, string Output) RunTool(string exe, string args)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi)!;
        string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(60_000);
        // Manche Werkzeuge (z. B. Sysmon) schreiben UTF-16 – Nullzeichen wuerden Meldungsfenster abschneiden.
        output = output.Replace("\0", "");
        if (p.ExitCode != 0 && string.IsNullOrWhiteSpace(output)) output = $"Exit-Code 0x{p.ExitCode:X8}";
        return (p.ExitCode, output);
    }
}
