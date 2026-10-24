using ScanMe.Core.Util;

namespace ScanMe.Core.Knowledge;

/// <summary>
/// Bekannte Windows-Kernprozesse mit erwartetem Pfad und Elternprozess.
/// Grundlage fuer Masquerading-Erkennung (z. B. svchost.exe ausserhalb von System32)
/// und fuer den Schutz kritischer Prozesse vor dem Beenden.
/// </summary>
public static class SystemProcesses
{
    public sealed record Profile(
        string Name,
        string[] ExpectedDirs,
        string[] ExpectedParents,
        bool Critical,
        bool SingleInstance,
        string Description);

    private static readonly string Sys32 = PathUtil.System32;
    private static readonly string Win = PathUtil.WindowsDir;
    private static readonly string Wow = PathUtil.SysWow64;

    private static readonly Dictionary<string, Profile> Profiles = new(StringComparer.OrdinalIgnoreCase)
    {
        ["smss.exe"] = new("smss.exe", [Sys32], ["System", "smss.exe"], true, false, "Sitzungsmanager – startet Windows-Sitzungen."),
        ["csrss.exe"] = new("csrss.exe", [Sys32], ["smss.exe"], true, false, "Client/Server Runtime – Kernbestandteil von Windows."),
        ["wininit.exe"] = new("wininit.exe", [Sys32], ["smss.exe"], true, true, "Windows-Startprozess für Sitzung 0."),
        ["winlogon.exe"] = new("winlogon.exe", [Sys32], ["smss.exe"], true, false, "Windows-Anmeldung."),
        ["services.exe"] = new("services.exe", [Sys32], ["wininit.exe"], true, true, "Dienststeuerungs-Manager."),
        ["lsass.exe"] = new("lsass.exe", [Sys32], ["wininit.exe"], true, true, "Lokale Sicherheitsautorität – verwaltet Passwörter und Anmeldungen. Beliebtes Angriffsziel (Credential Dumping)."),
        ["lsaiso.exe"] = new("lsaiso.exe", [Sys32], ["wininit.exe"], true, true, "Credential Guard (isolierte LSA)."),
        ["svchost.exe"] = new("svchost.exe", [Sys32, Wow], ["services.exe", "MsMpEng.exe"], true, false, "Generischer Host für Windows-Dienste."),
        ["fontdrvhost.exe"] = new("fontdrvhost.exe", [Sys32], ["wininit.exe", "winlogon.exe"], true, false, "Schriftarttreiber-Host."),
        ["dwm.exe"] = new("dwm.exe", [Sys32], ["winlogon.exe"], true, false, "Desktopfenster-Manager."),
        ["explorer.exe"] = new("explorer.exe", [Win], ["userinit.exe", "winlogon.exe", "explorer.exe", "sihost.exe"], false, false, "Windows-Explorer / Desktop-Shell."),
        ["userinit.exe"] = new("userinit.exe", [Sys32], ["winlogon.exe"], false, false, "Benutzeranmeldung-Initialisierung."),
        ["taskhostw.exe"] = new("taskhostw.exe", [Sys32], ["svchost.exe"], false, false, "Host für geplante Aufgaben."),
        ["sihost.exe"] = new("sihost.exe", [Sys32], ["svchost.exe"], false, false, "Shell Infrastructure Host."),
        ["runtimebroker.exe"] = new("RuntimeBroker.exe", [Sys32], ["svchost.exe"], false, false, "Berechtigungsverwaltung für Store-Apps."),
        ["spoolsv.exe"] = new("spoolsv.exe", [Sys32], ["services.exe"], false, true, "Druckwarteschlange."),
        ["conhost.exe"] = new("conhost.exe", [Sys32], [], false, false, "Konsolenfenster-Host."),
        ["ctfmon.exe"] = new("ctfmon.exe", [Sys32], [], false, false, "Texteingabe/Sprachleiste."),
        ["searchindexer.exe"] = new("SearchIndexer.exe", [Sys32], ["services.exe"], false, true, "Windows-Suchindizierung."),
        ["wuauclt.exe"] = new("wuauclt.exe", [Sys32], [], false, false, "Windows Update."),
        ["dllhost.exe"] = new("dllhost.exe", [Sys32, Wow], [], false, false, "COM-Surrogat."),
        ["rundll32.exe"] = new("rundll32.exe", [Sys32, Wow], [], false, false, "Führt DLL-Funktionen aus (häufig missbraucht)."),
        ["msmpeng.exe"] = new("MsMpEng.exe", [], [], true, true, "Microsoft Defender Antimalware-Dienst."),
        ["securityhealthservice.exe"] = new("SecurityHealthService.exe", [Sys32], ["services.exe"], true, true, "Windows-Sicherheitscenter."),
        ["wmiprvse.exe"] = new("WmiPrvSE.exe", [Path.Combine(Sys32, "wbem"), Path.Combine(Wow, "wbem")], ["svchost.exe"], false, false, "WMI-Anbieterhost."),
        ["audiodg.exe"] = new("audiodg.exe", [Sys32], ["svchost.exe"], false, false, "Windows-Audio-Isolation."),
        ["smartscreen.exe"] = new("smartscreen.exe", [Sys32], ["svchost.exe"], false, false, "Windows Defender SmartScreen."),
    };

    /// <summary>Prozesse, die niemals beendet werden duerfen (Bluescreen / Systemausfall).</summary>
    private static readonly HashSet<string> NeverKill = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "System Idle Process", "Registry", "Memory Compression", "Secure System",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe",
        "svchost.exe", "fontdrvhost.exe", "dwm.exe", "MsMpEng.exe", "NisSrv.exe", "SecurityHealthService.exe",
        "MpDefenderCoreService.exe", "vmmem", "vmmemWSL", "LsaIso.exe", "sgrmbroker.exe",
    };

    public static Profile? Get(string name) => Profiles.TryGetValue(name, out var p) ? p : null;

    public static IEnumerable<string> KnownNames => Profiles.Keys;

    public static bool IsNeverKill(string name) => NeverKill.Contains(name);

    /// <summary>Pseudo-Prozesse des Kernels ohne Image-Datei.</summary>
    public static bool IsKernelPseudoProcess(string name, int pid) =>
        pid is 0 or 4
        || name is "System" or "Idle" or "Registry" or "Memory Compression" or "Secure System" or "System Idle Process" or "vmmem" or "vmmemWSL";

    /// <summary>
    /// Prueft, ob ein Name einem Systemprozess zum Verwechseln aehnlich ist (Typosquatting: scvhost.exe, lsas.exe ...).
    /// </summary>
    public static string? FindLookalike(string name)
    {
        if (Profiles.ContainsKey(name)) return null;
        string n = name.ToLowerInvariant();
        foreach (var known in Profiles.Keys)
        {
            if (Math.Abs(known.Length - n.Length) > 2) continue;
            // Ein Tippfehler/Vertauscher reicht bei normal langen Namen (scvhost, lsasss);
            // zwei Abweichungen nur bei sehr langen Namen – sonst trifft es Programme wie "airhost.exe" (Zoom) vs. "sihost.exe".
            int dist = TextUtil.OsaDistance(known, n);
            if (dist == 1 && known.Length >= 7) return Profiles[known].Name;
            if (dist == 2 && known.Length >= 13) return Profiles[known].Name;
        }
        // Homoglyphen: 0 statt o, 1 statt l, rn statt m
        string folded = n.Replace('0', 'o').Replace('1', 'l').Replace("rn", "m");
        if (folded != n && Profiles.TryGetValue(folded, out var p)) return p.Name;
        return null;
    }
}
