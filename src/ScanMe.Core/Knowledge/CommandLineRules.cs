using System.Text.RegularExpressions;

namespace ScanMe.Core.Knowledge;

/// <summary>
/// Heuristische Regeln fuer verdaechtige Kommandozeilen (Prozesse, Autostarts, Tasks, WMI, PowerShell-Logs).
/// Orientiert an gaengigen Angreifertechniken (MITRE ATT&amp;CK) und "Living off the Land"-Binaries.
/// </summary>
public static class CommandLineRules
{
    public sealed record Rule(string Id, Regex Pattern, int Weight, string Text, string? Mitre = null);

    private static Rule R(string id, string pattern, int weight, string text, string? mitre = null) =>
        new(id, new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant), weight, text, mitre);

    public static readonly IReadOnlyList<Rule> Rules =
    [
        // --- PowerShell ---
        R("PS_ENCODED", @"(powershell|pwsh)(\.exe)?.*\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", 45, "PowerShell mit Base64-kodiertem Befehl (verschleierter Code)", "T1027"),
        R("PS_HIDDEN", @"(powershell|pwsh)(\.exe)?.*-(w|wi|win|window|windowstyle)\s+(h|hidden|1)\b", 25, "PowerShell mit verstecktem Fenster", "T1564.003"),
        R("PS_BYPASS", @"(powershell|pwsh)(\.exe)?.*-(ep|exec|executionpolicy)\s+(bypass|unrestricted)", 15, "PowerShell umgeht die Ausfuehrungsrichtlinie", "T1059.001"),
        R("PS_NOPROFILE_NONI", @"(powershell|pwsh)(\.exe)?.*-(nop|noprofile).*-(noni|noninteractive)", 10, "PowerShell nicht-interaktiv ohne Profil (typisch fuer automatisierte Payloads)"),
        R("PS_DOWNLOAD", @"(downloadstring|downloadfile|downloaddata|invoke-webrequest|iwr\s|invoke-restmethod|irm\s|net\.webclient|start-bitstransfer|wget\s|curl\s)", 30, "Laedt Inhalte aus dem Internet herunter", "T1105"),
        R("PS_IEX", @"(\biex\b|invoke-expression|\.invoke\(\)|&\s*\(\s*\$)", 30, "Fuehrt dynamisch erzeugten Code aus (Invoke-Expression)", "T1059.001"),
        R("PS_FROMB64", @"frombase64string", 20, "Dekodiert Base64-Daten zur Laufzeit", "T1140"),
        R("PS_REFLECTION", @"(reflection\.assembly|\[system\.reflection|assembly\]::load|virtualalloc|createthread)", 35, "Laedt Code direkt in den Speicher (dateilose Malware)", "T1620"),
        R("PS_AMSI", @"(amsiutils|amsiinitfailed|amsi\.dll|amsiscanbuffer)", 50, "Versuch, den Windows-Malwareschutz (AMSI) auszuhebeln", "T1562.001"),
        R("PS_DEFENDER_OFF", @"(set-mppreference.*-disable|add-mppreference.*-exclusion|disablerealtimemonitoring)", 50, "Versuch, Microsoft Defender zu deaktivieren oder Ausnahmen hinzuzufuegen", "T1562.001"),

        // --- LOLBins ---
        R("MSHTA_URL", @"mshta(\.exe)?\s+.*(https?:|javascript:|vbscript:)", 45, "mshta fuehrt Skript aus dem Internet / inline aus", "T1218.005"),
        R("RUNDLL_JS", @"rundll32(\.exe)?.*(javascript:|mshtml,runhtmlapplication)", 50, "rundll32 fuehrt JavaScript aus", "T1218.011"),
        R("RUNDLL_ODD", @"rundll32(\.exe)?\s+[""']?[a-z]:\\(users|programdata|windows\\temp)\\", 30, "rundll32 laedt eine DLL aus einem Benutzer-/Temp-Ordner", "T1218.011"),
        R("REGSVR_SCROBJ", @"regsvr32(\.exe)?.*(/i:\s*https?:|scrobj\.dll)", 50, "regsvr32 laedt Skript aus dem Internet (Squiblydoo)", "T1218.010"),
        R("CERTUTIL_DL", @"certutil(\.exe)?.*(-urlcache|-verifyctl|-decode|-decodehex)", 45, "certutil zum Herunterladen/Dekodieren missbraucht", "T1105"),
        R("BITSADMIN", @"bitsadmin(\.exe)?.*(/transfer|/addfile|/setnotifycmdline)", 35, "bitsadmin laedt Dateien herunter oder startet Befehle", "T1197"),
        R("WMIC_CREATE", @"wmic(\.exe)?.*process\s+call\s+create", 35, "wmic startet versteckt einen Prozess", "T1047"),
        R("WMIC_XSL", @"wmic(\.exe)?.*/format:\s*[""']?https?:", 50, "wmic laedt XSL-Skript aus dem Internet", "T1220"),
        R("MSIEXEC_URL", @"msiexec(\.exe)?.*/(i|q|package).*https?:", 35, "msiexec installiert Paket direkt aus dem Internet", "T1218.007"),
        R("SCRIPT_TEMP", @"(wscript|cscript)(\.exe)?.*\\(temp|appdata|public|programdata|downloads)\\.*\.(vbs|vbe|js|jse|wsf)", 40, "Skript-Host fuehrt Skript aus Benutzer-/Temp-Ordner aus", "T1059.005"),
        R("CMD_CHAIN_HIDDEN", @"cmd(\.exe)?\s+/c\s+.*(start\s+/b|&\s*del\s|>nul\s*2>&1.*&)", 15, "Verkettete versteckte cmd-Befehle"),
        R("CURL_EXEC", @"(curl|wget)(\.exe)?\s.*(-o|--output|>)\s*.*\.(exe|dll|ps1|bat|vbs|hta).*(&|;|\|)", 40, "Laedt eine ausfuehrbare Datei herunter und startet sie", "T1105"),
        R("RAW_IP_URL", @"https?://(\d{1,3}\.){3}\d{1,3}", 25, "Verbindung zu einer nackten IP-Adresse statt Domain"),
        R("PASTE_SITES", @"(pastebin\.com|paste\.ee|hastebin|ghostbin|transfer\.sh|anonfiles|discord(app)?\.com/api/webhooks|cdn\.discordapp\.com/attachments|raw\.githubusercontent\.com|ngrok\.io|trycloudflare\.com|telegram\.org/bot)", 30, "Bezieht Daten von Diensten, die haeufig fuer Malware genutzt werden"),

        // --- Anti-Forensik / Ransomware-Vorbereitung ---
        R("SHADOW_DELETE", @"(vssadmin(\.exe)?.*delete\s+shadows|wmic.*shadowcopy\s+delete|wbadmin.*delete\s+catalog)", 70, "Loescht Schattenkopien (typisch fuer Ransomware)", "T1490"),
        R("BCDEDIT_RECOVERY", @"bcdedit(\.exe)?.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", 60, "Deaktiviert die Windows-Wiederherstellung (typisch fuer Ransomware)", "T1490"),
        R("LOG_CLEAR", @"(wevtutil(\.exe)?\s+(cl|clear-log)|clear-eventlog)", 55, "Loescht Ereignisprotokolle (Spurenverwischung)", "T1070.001"),
        R("FW_DISABLE", @"netsh(\.exe)?.*(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+disable)", 45, "Schaltet die Windows-Firewall ab", "T1562.004"),

        // --- Persistenz / Konten ---
        R("NET_USER_ADD", @"net1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add", 45, "Legt einen neuen Benutzer an", "T1136.001"),
        R("NET_ADMIN_ADD", @"net1?(\.exe)?\s+localgroup\s+(administrators|administratoren)\s+\S+\s+/add", 55, "Fuegt einen Benutzer zur Administratorgruppe hinzu", "T1098"),
        R("SCHTASKS_CREATE", @"schtasks(\.exe)?.*/create", 20, "Legt eine geplante Aufgabe an", "T1053.005"),
        R("REG_RUN_ADD", @"reg(\.exe)?\s+add\s+.*\\currentversion\\run", 35, "Traegt sich in den Autostart ein", "T1547.001"),
        R("STICKY_KEYS", @"(sethc|utilman|osk|magnify|narrator|displayswitch)\.exe.*(debugger|copy|cmd\.exe)", 60, "Manipulation der Bedienungshilfen (Hintertuer am Anmeldebildschirm)", "T1546.008"),

        // --- Credential Access ---
        R("LSASS_DUMP", @"(procdump.*lsass|comsvcs(\.dll)?.*minidump|sekurlsa|mimikatz|lsass\.dmp)", 80, "Versuch, Passwoerter aus dem Speicher (LSASS) auszulesen", "T1003.001"),
        R("SAM_DUMP", @"reg(\.exe)?\s+save\s+hklm\\(sam|system|security)", 70, "Kopiert die Passwort-Datenbank (SAM) aus der Registry", "T1003.002"),
    ];

    public static IEnumerable<Rule> Match(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) yield break;
        foreach (var rule in Rules)
            if (rule.Pattern.IsMatch(commandLine))
                yield return rule;
    }
}
