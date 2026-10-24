using System.Security;
using System.Text;

namespace ScanMe.Core.Telemetry;

/// <summary>
/// Eigene, in ScanMe eingebaute Sysmon-Konfiguration (keine fremde Datei aus dem Internet).
/// Ausgelegt fuer Entwickler-PCs: vollstaendige Prozessherkunft, aber kein Rauschen durch
/// Build-Werkzeuge, node_modules oder Browser-Unterprozesse.
/// </summary>
public static class SysmonConfig
{
    public const string Marker = "ScanMe-Sysmon-Konfiguration v1";

    private static readonly string[] ScriptHosts =
    [
        "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe",
        "certutil.exe", "bitsadmin.exe", "msiexec.exe", "finger.exe", "curl.exe", "wmic.exe", "installutil.exe", "msbuild.exe",
    ];

    private static readonly string[] UserWritable = [@"\AppData\Local\Temp\", @"\Users\Public\", @"\Downloads\", @"\AppData\Roaming\", @"\ProgramData\"];

    private static readonly string[] RiskyExtensions = [".exe", ".dll", ".scr", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".lnk", ".iso", ".img", ".vhd", ".msi"];

    private static readonly string[] Browsers = ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "msedgewebview2.exe"];

    public static string Build()
    {
        var x = new StringBuilder();
        string E(string s) => SecurityElement.Escape(s)!;
        void Line(string s) => x.AppendLine(s);

        Line("<Sysmon schemaversion=\"4.50\">");
        Line($"  <!-- {Marker} -->");
        Line("  <HashAlgorithms>SHA256</HashAlgorithms>");
        Line("  <CheckRevocation>False</CheckRevocation>");
        Line("  <EventFiltering>");

        // 1: Prozessstart – alles, ausser Browser-Unterprozessen und Konsolenhosts (reines Rauschen)
        Line("    <RuleGroup name=\"ProcessCreate\" groupRelation=\"or\"><ProcessCreate onmatch=\"exclude\">");
        Line("      <Image condition=\"end with\">\\conhost.exe</Image>");
        foreach (var b in Browsers)
            Line($"      <Rule groupRelation=\"and\"><Image condition=\"end with\">\\{E(b)}</Image><ParentImage condition=\"end with\">\\{E(b)}</ParentImage></Rule>");
        Line("    </ProcessCreate></RuleGroup>");

        // 3/22: Netzwerk und DNS nur fuer Skript-Hosts und Programme aus Benutzerordnern
        foreach (var (tag, field) in new[] { ("NetworkConnect", "Image"), ("DnsQuery", "Image") })
        {
            Line($"    <RuleGroup name=\"{tag}\" groupRelation=\"or\"><{tag} onmatch=\"include\">");
            foreach (var h in ScriptHosts) Line($"      <{field} condition=\"end with\">\\{E(h)}</{field}>");
            foreach (var p in UserWritable) Line($"      <{field} condition=\"contains\">{E(p)}</{field}>");
            Line($"    </{tag}></RuleGroup>");
        }

        // 6/8/25/19-21: Treiber, Code-Injektion, Prozessmanipulation, WMI – alles (selten, wertvoll)
        foreach (var tag in new[] { "DriverLoad", "CreateRemoteThread", "ProcessTampering", "WmiEvent" })
            Line($"    <RuleGroup name=\"{tag}\" groupRelation=\"or\"><{tag} onmatch=\"exclude\" /></RuleGroup>");

        // 10: Zugriffe auf den Anmeldeprozess (Passwortdiebstahl), ohne Windows-eigene Zugriffe
        Line("    <RuleGroup name=\"LsassAccess\" groupRelation=\"or\"><ProcessAccess onmatch=\"include\">");
        Line("      <TargetImage condition=\"end with\">\\lsass.exe</TargetImage>");
        Line("    </ProcessAccess></RuleGroup>");
        Line("    <RuleGroup name=\"LsassAccessExclude\" groupRelation=\"or\"><ProcessAccess onmatch=\"exclude\">");
        foreach (var s in new[] { @"C:\Windows\System32\svchost.exe", @"C:\Windows\System32\wininit.exe", @"C:\Windows\System32\csrss.exe",
                                  @"C:\Windows\System32\lsm.exe", @"C:\Windows\System32\wbem\WmiPrvSE.exe", @"C:\Windows\System32\taskmgr.exe" })
            Line($"      <SourceImage condition=\"is\">{E(s)}</SourceImage>");
        Line("      <SourceImage condition=\"contains\">\\Windows Defender\\</SourceImage>");
        Line("      <SourceImage condition=\"contains\">\\Microsoft\\Windows Defender\\Platform\\</SourceImage>");
        Line("    </ProcessAccess></RuleGroup>");

        // 11: Neue Dateien an Einnistungsorten und riskante Dateitypen in Downloads/Temp
        Line("    <RuleGroup name=\"FileCreate\" groupRelation=\"or\"><FileCreate onmatch=\"include\">");
        Line("      <TargetFilename condition=\"contains\">\\Start Menu\\Programs\\Startup\\</TargetFilename>");
        Line("      <TargetFilename condition=\"contains\">\\Windows\\System32\\Tasks\\</TargetFilename>");
        Line("      <TargetFilename condition=\"contains\">\\Windows\\Tasks\\</TargetFilename>");
        Line("      <TargetFilename condition=\"end with\">.sys</TargetFilename>");
        foreach (var dir in new[] { @"\Downloads\", @"\AppData\Local\Temp\", @"\Users\Public\" })
            foreach (var ext in RiskyExtensions)
                Line($"      <Rule groupRelation=\"and\"><TargetFilename condition=\"contains\">{E(dir)}</TargetFilename><TargetFilename condition=\"end with\">{E(ext)}</TargetFilename></Rule>");
        Line("    </FileCreate></RuleGroup>");

        // 12-14: Registry-Einnistungsorte und Defender-Ausnahmen
        Line("    <RuleGroup name=\"Registry\" groupRelation=\"or\"><RegistryEvent onmatch=\"include\">");
        foreach (var k in new[] { @"\CurrentVersion\Run", @"\Image File Execution Options\", @"\Winlogon\", @"\Windows Defender\Exclusions\",
                                  @"\SilentProcessExit\", @"\Command Processor\AutoRun", @"\Session Manager\AppCertDlls", @"\Control\Lsa\" })
            Line($"      <TargetObject condition=\"contains\">{E(k)}</TargetObject>");
        Line("      <TargetObject condition=\"end with\">\\ImagePath</TargetObject>");
        Line("      <TargetObject condition=\"end with\">\\ServiceDll</TargetObject>");
        Line("    </RegistryEvent></RuleGroup>");

        // 15: Download-Herkunft (Zone.Identifier mit Quell-URL) fuer Dateien in Downloads
        Line("    <RuleGroup name=\"Downloads\" groupRelation=\"or\"><FileCreateStreamHash onmatch=\"include\">");
        Line("      <TargetFilename condition=\"contains\">\\Downloads\\</TargetFilename>");
        Line("    </FileCreateStreamHash></RuleGroup>");

        // Aus: zu viel Rauschen bzw. Datenschutz (Zwischenablage), FileDelete wuerde Kopien geloeschter Dateien archivieren
        foreach (var tag in new[] { "FileCreateTime", "ProcessTerminate", "ImageLoad", "RawAccessRead", "PipeEvent", "FileDelete", "ClipboardChange", "FileDeleteDetected" })
            Line($"    <RuleGroup name=\"{tag}Off\" groupRelation=\"or\"><{tag} onmatch=\"include\" /></RuleGroup>");

        Line("  </EventFiltering>");
        Line("</Sysmon>");
        return x.ToString();
    }
}
