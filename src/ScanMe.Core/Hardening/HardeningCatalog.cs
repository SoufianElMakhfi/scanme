using System.Management;
using Microsoft.Win32;
using ScanMe.Core.Actions;
using ScanMe.Core.Telemetry;
using ScanMe.Core.Util;

namespace ScanMe.Core.Hardening;

/// <summary>
/// Schutzmassnahmen, die Windows bereits mitbringt, die auf Privat-PCs aber meist aus sind.
/// Grundsatz wie in Unternehmen: erst Testmodus (nur protokollieren), dann scharf schalten.
/// </summary>
public static class HardeningCatalog
{
    public const string GroupAsr = "Angriffe blockieren (Defender-Regeln)";
    public const string GroupDefender = "Virenschutz verstärken";
    public const string GroupSystem = "Windows absichern";
    public const string GroupLogging = "Aufzeichnung für die Spurensuche";

    public static IReadOnlyList<HardeningItem> All { get; } = Build();

    // ------------------------------------------------------------------
    // Hilfsfunktionen
    // ------------------------------------------------------------------

    private static HardeningState FromAsr(byte? a) => a switch { 1 or 6 => HardeningState.On, 2 => HardeningState.Audit, _ => HardeningState.Off };

    private static HardeningItem Asr(string id, string title, string plain, string protects, string? devNote, HardeningMode? recommended) => new()
    {
        Id = "asr:" + id,
        Group = GroupAsr,
        Title = title,
        Plain = plain,
        Protects = protects,
        DevNote = devNote,
        SupportsAudit = true,
        Recommended = recommended,
        Read = () => FromAsr(MpPreference.AsrRules().TryGetValue(id, out var a) ? a : null),
        Apply = mode => MpPreference.SetAsr(id, mode switch { HardeningMode.On => 1, HardeningMode.Audit => 2, _ => 0 }),
    };

    /// <summary>Defender-Einstellung mit Werten 0 = aus, 1 = an, 2 = Testmodus.</summary>
    private static HardeningItem DefenderSwitch(string name, string id, string title, string plain, string protects, string? devNote, HardeningMode? recommended) => new()
    {
        Id = id,
        Group = GroupDefender,
        Title = title,
        Plain = plain,
        Protects = protects,
        DevNote = devNote,
        SupportsAudit = true,
        Recommended = recommended,
        Read = () => MpPreference.GetByte(name) switch { 1 => HardeningState.On, 2 => HardeningState.Audit, 0 => HardeningState.Off, _ => HardeningState.Unknown },
        Apply = mode => MpPreference.Set(name, (byte)(mode switch { HardeningMode.On => 1, HardeningMode.Audit => 2, _ => 0 })),
    };

    private static int? RegDword(string key, string name) => RegistryUtil.GetInt(key, name);

    private static string? SetRegDword(string key, string name, int? value)
    {
        try
        {
            var (root, sub) = RegistryUtil.Split(key);
            using var k = root!.CreateSubKey(sub, true);
            if (value == null) k.DeleteValue(name, false);
            else k.SetValue(name, value.Value, RegistryValueKind.DWord);
            return null;
        }
        catch (Exception ex) { return ex.Message; }
    }

    /// <summary>Registry-Schalter: An = Wert setzen, Aus = Ausgangswert (oder loeschen).</summary>
    private static HardeningItem RegSwitch(string id, string group, string title, string plain, string protects, string? devNote,
        string key, string name, int onValue, int? offValue, bool reboot, HardeningMode? recommended) => new()
    {
        Id = id,
        Group = group,
        Title = title,
        Plain = plain,
        Protects = protects,
        DevNote = devNote,
        NeedsReboot = reboot,
        Recommended = recommended,
        Read = () => RegDword(key, name) == onValue ? HardeningState.On : HardeningState.Off,
        Apply = mode => SetRegDword(key, name, mode == HardeningMode.On ? onValue : offValue),
    };

    /// <summary>Optionales Windows-Feature (Win32_OptionalFeature): An = Feature DEAKTIVIERT (Angriffsflaeche entfernt).</summary>
    private static HardeningItem FeatureRemoval(string id, string feature, string title, string plain, string protects, HardeningMode? recommended) => new()
    {
        Id = id,
        Group = GroupSystem,
        Title = title,
        Plain = plain,
        Protects = protects,
        NeedsReboot = true,
        Recommended = recommended,
        Read = () =>
        {
            try
            {
                using var s = new ManagementObjectSearcher($"SELECT InstallState FROM Win32_OptionalFeature WHERE Name = '{feature}'");
                var o = s.Get().Cast<ManagementBaseObject>().FirstOrDefault();
                if (o == null) return HardeningState.NotAvailable; // Feature existiert nicht mehr (z. B. neuere Windows-Versionen)
                return Convert.ToUInt32(o["InstallState"]) == 1 ? HardeningState.Off : HardeningState.On;
            }
            catch { return HardeningState.Unknown; }
        },
        Apply = mode =>
        {
            string verb = mode == HardeningMode.On ? "/disable-feature" : "/enable-feature";
            var (code, output) = ActionExecutor.RunTool("dism.exe", $"/online {verb} /featurename:{feature} /norestart");
            return code is 0 or 3010 ? null : output.Trim(); // 3010 = Neustart erforderlich
        },
    };

    private const string ProcessCreationAudit = "{0CCE922B-69AE-11D9-BED3-505054503030}";

    // ------------------------------------------------------------------
    // Katalog
    // ------------------------------------------------------------------

    private static List<HardeningItem> Build() =>
    [
        // --- Defender-Regeln zur Angriffsflaechenreduzierung (ASR) ---
        Asr("56a863a9-875e-4185-98a7-b882c64b5ce5", "Verwundbare Treiber blockieren",
            "Verhindert, dass bekannte, ausnutzbare Treiber geladen werden.",
            "Krypto-Miner und Ransomware, die über solche Treiber Virenschutz abschalten – genau so hat der Miner auf diesem PC WinRing0 genutzt.",
            "Alte Übertaktungs-, RGB- oder Lüftertools mit verwundbarem Treiber starten dann nicht mehr.", HardeningMode.On),
        Asr("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Passwortdiebstahl aus dem Anmeldeprozess blockieren",
            "Kein Programm darf die gespeicherten Windows-Anmeldedaten (LSASS) auslesen.",
            "Werkzeuge wie Mimikatz, mit denen Angreifer Passwörter aus dem Speicher stehlen.", null, HardeningMode.On),
        Asr("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Office darf keine Programme starten",
            "Word, Excel und PowerPoint können keine anderen Programme (z. B. PowerShell) mehr starten.",
            "Makro-Viren aus Phishing-Mails – der häufigste Weg in Firmennetze.",
            "Wer Office-Makros nutzt, die externe Programme aufrufen, sollte erst den Testmodus prüfen.", HardeningMode.On),
        Asr("26190899-1602-49e8-8b27-eb1d0a1ce869", "Outlook darf keine Programme starten",
            "Das Mailprogramm kann keine anderen Programme starten.",
            "Schädliche Anhänge und Links, die direkt aus Outlook heraus etwas ausführen.", null, HardeningMode.On),
        Asr("3b576869-a4ec-4529-8536-b80a7769e899", "Office darf keine Programme erzeugen",
            "Office-Dokumente können keine ausführbaren Dateien auf die Festplatte schreiben.",
            "Phishing-Dokumente, die Schadsoftware ablegen.", null, HardeningMode.On),
        Asr("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Office darf keinen Code in andere Programme einschleusen",
            "Office kann sich nicht in fremde Prozesse einklinken.",
            "Getarnte Schadsoftware, die sich in harmlosen Programmen versteckt.", null, HardeningMode.On),
        Asr("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Gefährliche Funktionen in Office-Makros blockieren",
            "Makros dürfen keine tiefen Windows-Funktionen aufrufen.",
            "Makro-Malware, die Windows-Funktionen missbraucht.", null, HardeningMode.On),
        Asr("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Ausführbare E-Mail-Anhänge blockieren",
            "Programme und Skripte aus E-Mail-Anhängen werden nicht ausgeführt.",
            "Klassische Phishing-Anhänge (rechnung.pdf.exe, .js, .vbs).", null, HardeningMode.On),
        Asr("d3e037e1-3eb8-44c8-a917-57927947596d", "Skripte dürfen keine Downloads starten",
            "JavaScript- und VBScript-Dateien können keine heruntergeladenen Programme starten.",
            "Phishing-Skripte, die Schadsoftware nachladen.",
            "Betrifft nur Windows Script Host (.js/.vbs per Doppelklick) – nicht Node.js.", HardeningMode.On),
        Asr("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Verschleierte Skripte blockieren",
            "Skripte, deren Inhalt absichtlich unlesbar gemacht wurde, werden gestoppt.",
            "ClickFix-Befehle und andere getarnte PowerShell-/JavaScript-Angriffe.",
            "Kann eigene stark gepackte oder Base64-kodierte Skripte treffen – deshalb zuerst Testmodus.", HardeningMode.Audit),
        Asr("e6db77e5-3df2-4cf1-b95a-636979351e5b", "Unsichtbare WMI-Autostarts blockieren",
            "Programme können sich nicht über WMI-Ereignisse heimlich in den Autostart eintragen.",
            "Dateilose Malware und staatliche Angreifergruppen.", null, HardeningMode.On),
        Asr("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Unsignierte Programme vom USB-Stick blockieren",
            "Unbekannte Programme auf USB-Sticks werden nicht gestartet.",
            "Infizierte USB-Sticks.",
            "Eigene, unsignierte Tools auf USB-Sticks starten dann nicht.", HardeningMode.On),
        Asr("c1db55ab-c21a-4637-bb3f-a12568109d35", "Erweiterter Ransomware-Schutz",
            "Unbekannte Programme, die sich wie Erpressungstrojaner verhalten, werden gestoppt.",
            "Ransomware, die Ihre Dateien verschlüsselt.",
            "Kann frisch selbst kompilierte Programme vorsichtshalber stoppen – deshalb zuerst Testmodus.", HardeningMode.Audit),
        Asr("d1e49aac-8f56-4280-b9ba-993a6d77406c", "Fernstart über PsExec/WMI blockieren",
            "Programme können nicht per PsExec oder WMI ferngestartet werden.",
            "Angreifer, die sich im Netzwerk ausbreiten.",
            "Stört Admin- und Build-Werkzeuge, die Prozesse per WMI starten. Nur bei Bedarf.", null),
        Asr("01443614-cd74-433a-b99e-2ecdc07bfc25", "Nur verbreitete Programme erlauben",
            "Sehr neue oder seltene Programme werden blockiert, bis Microsoft sie kennt.",
            "Brandneue Malware.",
            "Für Entwickler NICHT geeignet: blockiert jedes selbst kompilierte Programm.", null),

        // --- Defender ---
        DefenderSwitch("PUAProtection", "def:pua", "Werbe- und Bündelsoftware blockieren (PUA)",
            "Defender blockiert Adware, Toolbars, Scareware und gebündelte Installer.",
            "Ungefragt mitinstallierte Programme, die z. B. bei Cheat- oder Download-Seiten mitkommen.", null, HardeningMode.On),
        DefenderSwitch("EnableNetworkProtection", "def:network", "Netzwerkschutz",
            "Alle Programme – nicht nur der Browser – werden an bekannten Phishing- und Malware-Seiten gehindert.",
            "Malware, die ihren Steuerserver kontaktiert, und Phishing-Links aus beliebigen Programmen.", null, HardeningMode.On),
        DefenderSwitch("EnableControlledFolderAccess", "def:cfa", "Überwachter Ordnerzugriff (Ransomware-Schutz)",
            "Nur vertrauenswürdige Programme dürfen Dateien in Dokumente, Bilder, Desktop usw. ändern.",
            "Erpressungstrojaner, die persönliche Dateien verschlüsseln.",
            "Blockiert auch Node.js, Python, Compiler und Git, wenn sie in diese Ordner schreiben. Für Entwickler: nur Testmodus oder Projekte außerhalb dieser Ordner ablegen.", HardeningMode.Audit),
        new HardeningItem
        {
            Id = "def:cloud",
            Group = GroupDefender,
            Title = "Cloud-Schutz auf hoher Stufe",
            Plain = "Defender fragt bei unbekannten Dateien sofort die Microsoft-Cloud und blockiert verdächtige Dateien schneller.",
            Protects = "Brandneue Malware, für die es noch keine Signaturen gibt.",
            Recommended = HardeningMode.On,
            Read = () => MpPreference.GetByte("MAPSReporting") == 2 && (MpPreference.GetByte("CloudBlockLevel") ?? 0) >= 2 ? HardeningState.On : HardeningState.Off,
            Apply = mode => mode == HardeningMode.On
                ? MpPreference.Set("MAPSReporting", (byte)2) ?? MpPreference.Set("SubmitSamplesConsent", (byte)1) ?? MpPreference.Set("CloudBlockLevel", (byte)2)
                : MpPreference.Set("CloudBlockLevel", (byte)0),
        },

        // --- System ---
        RegSwitch("sys:hvci", GroupSystem, "Speicherintegrität (Kernisolierung)",
            "Schützt den Windows-Kern per Virtualisierung – Schadcode kann sich dort nicht einschleusen.",
            "Rootkits und manipulierte Treiber.",
            "Inkompatible alte Treiber (manche Hardware-Tools, ältere Anti-Cheats) laden dann nicht. Windows-Sicherheit zeigt sie unter Kernisolierung an.",
            @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", 1, 0, true, HardeningMode.On),
        RegSwitch("sys:driverblocklist", GroupSystem, "Microsoft-Sperrliste für Treiber",
            "Windows blockiert Treiber, die Microsoft als gefährlich bekannt sind.",
            "Ausnutzbare Treiber (BYOVD).", null,
            @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable", 1, 0, true, HardeningMode.On),
        RegSwitch("sys:lsa", GroupSystem, "Schutz der Anmeldedaten (LSA-Schutz)",
            "Der Windows-Anmeldeprozess läuft geschützt – fremde Programme können ihn nicht auslesen.",
            "Passwort-Diebstahl aus dem Speicher.", null,
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 1, null, true, HardeningMode.On),
        RegSwitch("sys:fileext", GroupSystem, "Dateiendungen immer anzeigen",
            "Der Explorer zeigt „rechnung.pdf.exe“ statt nur „rechnung.pdf“.",
            "Phishing-Dateien, die sich als Dokument tarnen.", null,
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", 0, 1, false, HardeningMode.On),
        RegSwitch("sys:wsh", GroupSystem, "Windows Script Host abschalten",
            ".js-, .vbs- und .wsf-Dateien werden per Doppelklick nicht mehr ausgeführt.",
            "Einer der häufigsten Phishing-Anhänge.",
            "Betrifft NICHT Node.js, Python oder PowerShell. Sehr alte Installer mit VBS-Skripten können scheitern.",
            @"HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled", 0, null, false, HardeningMode.On),
        RegSwitch("sys:autorun", GroupSystem, "Autostart von USB-Sticks und CDs abschalten",
            "Eingesteckte Datenträger starten nichts automatisch.",
            "Infizierte USB-Sticks.", null,
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255, null, false, HardeningMode.On),
        FeatureRemoval("sys:smb1", "SMB1Protocol", "Veraltetes SMBv1 entfernen",
            "Entfernt das unsichere Dateifreigabe-Protokoll aus den 1990ern.",
            "Würmer wie WannaCry.", HardeningMode.On),
        FeatureRemoval("sys:ps2", "MicrosoftWindowsPowerShellV2Root", "Alte PowerShell 2.0 entfernen",
            "Entfernt die veraltete PowerShell-Version ohne Sicherheitsprotokollierung.",
            "Angreifer, die auf PowerShell 2.0 ausweichen, um Protokollierung und AMSI zu umgehen.", HardeningMode.On),

        // --- Aufzeichnung ---
        new HardeningItem
        {
            Id = "log:process",
            Group = GroupLogging,
            Title = "Programmstarts mit Befehl und Herkunft aufzeichnen",
            Plain = "Windows protokolliert jeden Programmstart: welches Programm, mit welchem Befehl, gestartet von welchem anderen Programm.",
            Protects = "Ermöglicht die Frage „Wer hat das gestartet?“ (z. B. Ihr Terminal oder ein unbekanntes Programm) – auch nachträglich.",
            DevNote = "Kommandozeilen werden im Sicherheitsprotokoll gespeichert. Passwörter, die Sie als Befehlsparameter eingeben, stehen dann dort.",
            Recommended = HardeningMode.On,
            Read = () =>
            {
                bool cmd = RegDword(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "ProcessCreationIncludeCmdLine_Enabled") == 1;
                var (code, output) = ActionExecutor.RunTool("auditpol.exe", $"/get /subcategory:{ProcessCreationAudit} /r");
                if (code != 0) return HardeningState.Unknown;
                var line = output.Split('\n').Skip(1).FirstOrDefault(l => l.Contains(','))?.Trim();
                bool audit = line != null && int.TryParse(line.Split(',').Last().Trim(), out int v) && (v & 1) == 1;
                return audit && cmd ? HardeningState.On : HardeningState.Off;
            },
            Apply = mode =>
            {
                string flag = mode == HardeningMode.On ? "enable" : "disable";
                var (code, output) = ActionExecutor.RunTool("auditpol.exe", $"/set /subcategory:{ProcessCreationAudit} /success:{flag}");
                if (code != 0) return output.Trim();
                return SetRegDword(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "ProcessCreationIncludeCmdLine_Enabled", mode == HardeningMode.On ? 1 : null);
            },
        },
        new HardeningItem
        {
            Id = "log:sysmon",
            Group = GroupLogging,
            Title = "Profi-Aufzeichnung mit Microsoft Sysmon",
            Plain = "Installiert das kostenlose Microsoft-Werkzeug Sysmon (Sysinternals) mit einer ScanMe-Konfiguration: vollständige Startketten, " +
                    "Verbindungen von Skript-Programmen, Treiber, Zugriffe auf Anmeldedaten und neue Autostarts. ScanMe lädt es direkt von Microsoft und prüft vorher die Signatur.",
            Protects = "ScanMe erkennt damit, ob ein PowerShell-Befehl aus Ihrem Terminal, Editor oder KI-Tool kam – oder aus Word, dem Browser oder einem unbekannten Programm.",
            DevNote = "Empfohlen für alle, die viel mit Skripten und KI-Tools arbeiten. Kommandozeilen (auch Passwörter als Parameter) landen im Sysmon-Protokoll. " +
                      "Eine bereits vorhandene Sysmon-Installation (z. B. von der Firmen-IT) wird nicht verändert.",
            Recommended = null,
            Read = () => SysmonService.IsInstalled() ? HardeningState.On : HardeningState.Off,
            Apply = mode => mode == HardeningMode.Off ? SysmonService.Uninstall() : SysmonService.Install(),
        },
        RegSwitch("log:scriptblock", GroupLogging, "Alle PowerShell-Befehle aufzeichnen",
            "PowerShell protokolliert jeden ausgeführten Befehl – nicht nur die, die es selbst für verdächtig hält.",
            "Vollständige Spurensuche bei Skript-Angriffen.",
            "Auch Passwörter oder API-Schlüssel, die direkt in Skripten stehen, landen im Protokoll. Schlüssel besser in Umgebungsvariablen oder einem Tresor halten.",
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", 1, null, false, HardeningMode.On),
        new HardeningItem
        {
            Id = "log:size",
            Group = GroupLogging,
            Title = "Protokolle vergrößern (256 MB)",
            Plain = "Sicherheits- und PowerShell-Protokoll behalten Einträge deutlich länger, bevor alte überschrieben werden.",
            Protects = "Spuren eines Angriffs sind auch nach Wochen noch auffindbar.",
            Recommended = HardeningMode.On,
            Read = () =>
            {
                var (code, output) = ActionExecutor.RunTool("wevtutil.exe", "gl Security");
                var line = output.Split('\n').FirstOrDefault(l => l.TrimStart().StartsWith("maxSize", StringComparison.OrdinalIgnoreCase));
                return code == 0 && line != null && long.TryParse(line.Split(':').Last().Trim(), out long size) && size >= 200L * 1024 * 1024
                    ? HardeningState.On : HardeningState.Off;
            },
            Apply = mode =>
            {
                long size = mode == HardeningMode.On ? 268435456 : 20971520;
                foreach (var log in new[] { "Security", "Microsoft-Windows-PowerShell/Operational" })
                {
                    var (code, output) = ActionExecutor.RunTool("wevtutil.exe", $"sl \"{log}\" /ms:{size}");
                    if (code != 0) return output.Trim();
                }
                return null;
            },
        },
    ];
}
