using System.Diagnostics.Eventing.Reader;
using System.Management;
using ScanMe.Core.Engine;
using ScanMe.Core.Models;
using ScanMe.Core.Util;

namespace ScanMe.Core.Scanners;

/// <summary>
/// Stabilitaet und Kompatibilitaet: Geraetefehler, Bluescreens, App-Abstuerze, Speicherplatz,
/// Festplattenzustand, Virenscanner-Konflikte.
/// </summary>
public sealed class CompatibilityScanner : IScanner
{
    public string Id => "compat";
    public string Name => "Kompatibilitaet & Stabilitaet";
    public string Description => "Treiber-/Geraetefehler, Bluescreens, abstuerzende Programme, Speicherplatz, Festplatten-SMART.";
    public bool InQuickScan => false;

    public Task ScanAsync(ScanContext ctx)
    {
        ctx.Status("Geraete-Manager …");
        DeviceProblems(ctx);
        ctx.Status("Bluescreens & Abstuerze …");
        Crashes(ctx);
        ctx.Status("Datentraeger …");
        Disks(ctx);
        ctx.Status("Systemzustand …");
        SystemState(ctx);
        return Task.CompletedTask;
    }

    private Finding Add(ScanContext ctx, string title, int weight, string desc, string expl, string rec)
    {
        var f = new Finding { ScannerId = Id, Category = FindingCategory.Compatibility, Title = title, Description = desc, Explanation = expl, Recommendation = rec };
        f.AddIndicator("COMPAT", title, weight);
        ctx.Add(f);
        return f;
    }

    private static string ErrorCodeText(int code) => code switch
    {
        1 => "Geraet ist nicht richtig konfiguriert",
        3 => "Treiber beschaedigt oder zu wenig Speicher",
        10 => "Geraet kann nicht gestartet werden",
        12 => "Nicht genuegend freie Ressourcen",
        14 => "Neustart erforderlich",
        18 => "Treiber muss neu installiert werden",
        19 => "Registrierungsinformationen beschaedigt",
        21 => "Geraet wird entfernt",
        28 => "Kein Treiber installiert",
        31 => "Treiber konnte nicht geladen werden",
        32 => "Treiberdienst deaktiviert",
        37 => "Treiber hat einen Fehler gemeldet",
        39 => "Treiber beschaedigt oder fehlt",
        43 => "Geraet hat ein Problem gemeldet (oft Hardware/Treiber-Absturz)",
        48 => "Treiber wurde wegen Inkompatibilitaet blockiert",
        52 => "Digitale Signatur des Treibers kann nicht ueberprueft werden",
        _ => $"Fehlercode {code}",
    };

    private void DeviceProblems(ScanContext ctx)
    {
        try
        {
            using var s = new ManagementObjectSearcher("SELECT Name, DeviceID, ConfigManagerErrorCode, PNPClass FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0");
            foreach (ManagementObject mo in s.Get())
            {
                using (mo)
                {
                    int code = Convert.ToInt32(mo["ConfigManagerErrorCode"] ?? 0);
                    if (code is 22 or 24 or 45) continue; // deaktiviert / nicht angeschlossen
                    string name = mo["Name"]?.ToString() ?? mo["DeviceID"]?.ToString() ?? "Unbekanntes Geraet";
                    var f = Add(ctx, $"Geraeteproblem: {name}", code is 52 or 48 ? 25 : 15,
                        $"{name}: {ErrorCodeText(code)} (Code {code}).",
                        "Fehlerhafte oder fehlende Treiber verursachen Abstuerze, Leistungsprobleme oder fehlende Funktionen.",
                        code == 28 ? "Treiber ueber Windows Update (optionale Updates) oder von der Herstellerseite installieren."
                                   : "Im Geraete-Manager Treiber aktualisieren oder Geraet deinstallieren und neu erkennen lassen.");
                    f.Detail("Geraete-ID", mo["DeviceID"]?.ToString()).Detail("Klasse", mo["PNPClass"]?.ToString());
                }
            }
        }
        catch { ctx.Note("Geraeteliste nicht abrufbar."); }
    }

    private static IEnumerable<EventRecord> Query(string log, string xpath, int max = 500)
    {
        EventLogReader reader;
        try { reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = true }); }
        catch { yield break; }
        using (reader)
        {
            for (int i = 0; i < max; i++)
            {
                EventRecord? r;
                try { r = reader.ReadEvent(); } catch { yield break; }
                if (r == null) yield break;
                using (r) yield return r;
            }
        }
    }

    private void Crashes(ScanContext ctx)
    {
        long d30 = 30L * 24 * 3600 * 1000;

        var bsods = Query("System", $"*[System[Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and (EventID=1001) and TimeCreated[timediff(@SystemTime) <= {d30}]]]")
            .Select(r => (When: r.TimeCreated, Code: SafeProp(r, 0))).ToList();
        if (bsods.Count > 0)
        {
            string dumps = Path.Combine(PathUtil.WindowsDir, "Minidump");
            int dumpCount = Directory.Exists(dumps) ? SafeCount(dumps) : 0;
            var f = Add(ctx, $"{bsods.Count} Bluescreen(s) in 30 Tagen", bsods.Count >= 3 ? 40 : 25,
                string.Join("; ", bsods.Take(10).Select(b => $"{b.When:g}: Stopcode {b.Code}")),
                "Bluescreens werden meist von fehlerhaften Treibern, defektem RAM oder Ueberhitzung verursacht – selten auch von Rootkits.",
                "Treiber (v. a. Grafik, Chipsatz) aktualisieren, Arbeitsspeicher pruefen (mdsched.exe). Minidumps lassen sich mit WinDbg analysieren.");
            f.Detail("Minidumps", $"{dumpCount} in {dumps}");
        }

        int unexpected = Query("System", $"*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=41) and TimeCreated[timediff(@SystemTime) <= {d30}]]]").Count();
        if (unexpected >= 2)
            Add(ctx, $"{unexpected} unerwartete Abschaltungen in 30 Tagen", unexpected >= 5 ? 25 : 15,
                "Windows wurde mehrfach nicht ordnungsgemaess heruntergefahren (Absturz, Stromausfall, Einfrieren).",
                "Haeufige harte Abschaltungen deuten auf Hardware-, Netzteil- oder Treiberprobleme hin.",
                "Temperaturen und Netzteil pruefen, Treiber aktualisieren.");

        long d14 = 14L * 24 * 3600 * 1000;
        var appCrashes = Query("Application", $"*[System[Provider[@Name='Application Error'] and (EventID=1000) and TimeCreated[timediff(@SystemTime) <= {d14}]]]", 1000)
            .Select(r => (App: SafeProp(r, 0) ?? "?", Module: SafeProp(r, 3) ?? "?")).ToList();
        foreach (var g in appCrashes.GroupBy(c => c.App, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() >= 3).OrderByDescending(g => g.Count()).Take(10))
        {
            var modules = g.GroupBy(c => c.Module, StringComparer.OrdinalIgnoreCase).OrderByDescending(m => m.Count()).Select(m => $"{m.Key} ({m.Count()}x)").Take(3);
            Add(ctx, $"Programm stuerzt haeufig ab: {g.Key}", 15,
                $"{g.Key} ist in 14 Tagen {g.Count()}-mal abgestuerzt. Fehlerhaftes Modul: {string.Join(", ", modules)}.",
                "Wiederholte Abstuerze deuten auf Inkompatibilitaet, defekte Installation oder eine eingeschleuste DLL (z. B. Overlay, alter Virenscanner) hin.",
                "Programm aktualisieren oder neu installieren. Ist das fehlerhafte Modul eine fremde DLL, das zugehoerige Programm pruefen.");
        }

        // Fremde DLLs, die in vielen verschiedenen Programmen Abstuerze verursachen
        var injected = appCrashes.Where(c => !c.Module.Equals(c.App, StringComparison.OrdinalIgnoreCase)
                                             && !c.Module.StartsWith("ntdll", StringComparison.OrdinalIgnoreCase)
                                             && !c.Module.StartsWith("KERNELBASE", StringComparison.OrdinalIgnoreCase)
                                             && !c.Module.StartsWith("ucrtbase", StringComparison.OrdinalIgnoreCase)
                                             && !c.Module.StartsWith("unknown", StringComparison.OrdinalIgnoreCase))
            .GroupBy(c => c.Module, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Select(c => c.App).Distinct(StringComparer.OrdinalIgnoreCase).Count() >= 3);
        foreach (var g in injected)
            Add(ctx, $"Modul verursacht Abstuerze in mehreren Programmen: {g.Key}", 25,
                $"{g.Key} war an Abstuerzen von {string.Join(", ", g.Select(c => c.App).Distinct().Take(6))} beteiligt.",
                "Eine DLL, die in viele Programme geladen wird und dort abstuerzt, stammt oft von Overlays, Hooks, Virenscannern – oder Malware.",
                "Herausfinden, zu welchem Programm das Modul gehoert (Dateisuche), und dieses aktualisieren oder entfernen.");
    }

    private void Disks(ScanContext ctx)
    {
        try
        {
            var sys = new DriveInfo(Path.GetPathRoot(PathUtil.WindowsDir) ?? "C:\\");
            double freePct = (double)sys.AvailableFreeSpace / sys.TotalSize * 100;
            if (freePct < 15)
                Add(ctx, $"Wenig Speicherplatz auf {sys.Name} ({freePct:0} % frei)", freePct < 5 ? 35 : freePct < 10 ? 20 : 10,
                    $"Frei: {TextUtil.FormatBytes(sys.AvailableFreeSpace)} von {TextUtil.FormatBytes(sys.TotalSize)}.",
                    "Unter 10 % freiem Speicher scheitern Windows-Updates und das System wird langsam.",
                    "Datentraegerbereinigung (cleanmgr) bzw. Einstellungen → System → Speicher → Bereinigungsempfehlungen.");
        }
        catch { }

        try
        {
            using var s = new ManagementObjectSearcher(@"root\wmi", "SELECT InstanceName, PredictFailure FROM MSStorageDriver_FailurePredictStatus");
            foreach (ManagementObject mo in s.Get())
                using (mo)
                    if (mo["PredictFailure"] as bool? == true)
                        Add(ctx, "Festplatte meldet bevorstehenden Ausfall (SMART)", 70,
                            $"Datentraeger {mo["InstanceName"]} meldet per SMART einen drohenden Ausfall.",
                            "Die Festplatte/SSD kann jederzeit ausfallen – Datenverlust droht.",
                            "SOFORT ein Backup aller wichtigen Daten anlegen und den Datentraeger ersetzen.");
        }
        catch { /* ohne Adminrechte / bei NVMe nicht verfuegbar */ }
    }

    private void SystemState(ScanContext ctx)
    {
        var av = SecurityConfigScanner.ThirdPartyAntivirus();
        if (av.Count >= 2)
            Add(ctx, "Mehrere Virenscanner gleichzeitig aktiv", 30,
                $"Aktiv: {string.Join(", ", av)}.",
                "Mehrere Echtzeit-Virenscanner behindern sich gegenseitig: Abstuerze, Bremsen und Luecken im Schutz.",
                "Nur einen Virenscanner behalten (Microsoft Defender ist fuer die meisten ausreichend).");

        bool reboot = RegistryUtil.SubKeys(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing").Contains("RebootPending")
                      || RegistryUtil.SubKeys(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update").Contains("RebootRequired");
        if (reboot)
            Add(ctx, "Neustart ausstehend", 10, "Updates warten auf einen Neustart.",
                "Sicherheitsupdates werden erst nach dem Neustart wirksam.", "PC neu starten.");

        var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
        if (uptime.TotalDays > 14)
            Add(ctx, $"PC laeuft seit {uptime.TotalDays:0} Tagen ohne Neustart", 5,
                "Lange Laufzeiten verhindern das Einspielen von Updates und lassen Speicherlecks wachsen.",
                "Gelegentliche Neustarts halten das System stabil.", "PC neu starten (Hinweis: 'Herunterfahren' bei Schnellstart ist kein echter Neustart).");
    }

    private static string? SafeProp(EventRecord r, int i)
    {
        try { return r.Properties.Count > i ? r.Properties[i].Value?.ToString() : null; }
        catch { return null; }
    }

    private static int SafeCount(string dir)
    {
        try { return Directory.GetFiles(dir, "*.dmp").Length; } catch { return 0; }
    }
}
