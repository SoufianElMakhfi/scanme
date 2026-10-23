using ScanMe.Core.Inventory;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Trust;
using ScanMe.Core.Util;

namespace ScanMe.Core.Actions;

/// <summary>
/// Letzte Verteidigungslinie: prueft JEDE Aktion unmittelbar vor der Ausfuehrung erneut –
/// unabhaengig davon, was der Scanner gemeldet hat. Windows-Komponenten werden nie angetastet.
/// </summary>
public static class SafetyGuard
{
    private static readonly string[] AllowedUnderWindows =
    [
        Path.Combine(PathUtil.WindowsDir, "Temp"),
        Path.Combine(PathUtil.WindowsDir, "Tasks"),
        Path.Combine(PathUtil.System32, "Tasks"),
    ];

    /// <summary>Darf diese Datei verschoben/geloescht werden? Liefert null wenn ja, sonst den Grund.</summary>
    public static string? CheckFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "Kein Pfad angegeben.";
        string full = PathUtil.Normalize(path);
        if (!File.Exists(full)) return "Datei existiert nicht (mehr).";

        string self = Environment.ProcessPath ?? "";
        if (full.Equals(self, StringComparison.OrdinalIgnoreCase) || PathUtil.IsUnder(full, AppContext.BaseDirectory.TrimEnd('\\')))
            return "ScanMe schuetzt sich selbst.";

        if (PathUtil.IsUnderWindowsDirectory(full) && !AllowedUnderWindows.Any(a => PathUtil.IsUnder(full, a)))
        {
            // Ausnahme: nachweislich NICHT von Microsoft signierte Treiber/Programme ausserhalb von WinSxS
            var t = FileTrustService.Shared.Get(full);
            if (t.IsMicrosoftSigned || t.Signature == SignatureState.Valid || PathUtil.IsUnder(full, Path.Combine(PathUtil.WindowsDir, "WinSxS")))
                return "Datei liegt im Windows-Verzeichnis und ist signiert – wird zum Schutz des Systems nicht angetastet.";
        }

        var trust = FileTrustService.Shared.Get(full);
        if (trust.IsWindowsComponent) return "Verifizierte Windows-Komponente – wird nie verschoben oder geloescht.";
        if (trust.IsMicrosoftSigned) return "Von Microsoft signierte Datei – wird zum Schutz des Systems nicht angetastet.";

        string defender = Path.Combine(PathUtil.ProgramData, @"Microsoft\Windows Defender");
        if (PathUtil.IsUnder(full, defender) || PathUtil.IsUnder(full, Path.Combine(PathUtil.ProgramFiles, "Windows Defender")))
            return "Bestandteil von Microsoft Defender.";

        if (full.Equals(Path.Combine(PathUtil.System32, @"drivers\etc\hosts"), StringComparison.OrdinalIgnoreCase))
            return "Die Hosts-Datei wird nur ueber 'Zuruecksetzen' bearbeitet.";

        return null;
    }

    /// <summary>Darf dieser Prozess beendet werden? Liefert null wenn ja, sonst den Grund.</summary>
    public static string? CheckProcess(int pid)
    {
        if (pid is 0 or 4) return "Kernel-Prozess.";
        if (pid == Environment.ProcessId) return "ScanMe beendet sich nicht selbst.";

        System.Diagnostics.Process p;
        try { p = System.Diagnostics.Process.GetProcessById(pid); }
        catch { return "Prozess laeuft nicht mehr."; }

        using (p)
        {
            string name = p.ProcessName + ".exe";
            string? path = ProcessSnapshot.QueryImagePath(pid);
            if (SystemProcesses.IsKernelPseudoProcess(p.ProcessName, pid)) return "Kernel-Pseudoprozess.";

            bool genuine = path != null && FileTrustService.Shared.Get(path).IsWindowsComponent;
            // Echte kritische Systemprozesse NIE beenden. Faelschungen gleichen Namens (z. B. svchost.exe in AppData) duerfen beendet werden.
            if (SystemProcesses.IsNeverKill(name) && (genuine || path == null))
                return $"{name} ist ein kritischer Windows-Prozess – Beenden wuerde einen Systemabsturz ausloesen.";
            if (genuine && name.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                return "Der Windows-Explorer (Desktop/Taskleiste) wird nicht beendet.";
        }
        return null;
    }

    /// <summary>Registry-Pfade, deren Werte nie geloescht werden duerfen (nur gezielt auf Standard setzen).</summary>
    public static string? CheckRegistryDelete(string key, string value)
    {
        string k = key.ToUpperInvariant();
        if (k.Contains(@"\CONTROL\LSA") && !value.Equals("RunAsPPL", StringComparison.OrdinalIgnoreCase))
            return "LSA-Werte werden nicht geloescht (Anmeldung koennte unmoeglich werden).";
        if (k.EndsWith(@"\WINLOGON") && value is "Shell" or "Userinit")
            return "Winlogon-Werte werden nur auf den Windows-Standard zurueckgesetzt, nie geloescht.";
        return null;
    }

    /// <summary>Dienste, die nie deaktiviert werden duerfen.</summary>
    public static string? CheckService(string name)
    {
        string[] critical = ["RpcSs", "DcomLaunch", "RpcEptMapper", "LSM", "SamSs", "EventLog", "PlugPlay", "Power", "BFE", "mpssvc",
                             "WinDefend", "WdNisSvc", "SecurityHealthService", "wscsvc", "CryptSvc", "Dhcp", "Dnscache", "nsi", "Winmgmt",
                             "ProfSvc", "UserManager", "Schedule", "gpsvc", "AudioSrv", "BrokerInfrastructure", "CoreMessagingRegistrar",
                             "StateRepository", "SystemEventsBroker", "TimeBrokerSvc", "wuauserv", "TrustedInstaller", "msiserver"];
        if (critical.Contains(name, StringComparer.OrdinalIgnoreCase)) return $"{name} ist ein Kerndienst von Windows.";

        string? image = RegistryUtil.GetString($@"HKLM\SYSTEM\CurrentControlSet\Services\{name}", "ImagePath");
        string? dll = RegistryUtil.GetString($@"HKLM\SYSTEM\CurrentControlSet\Services\{name}\Parameters", "ServiceDll");
        string? file = dll != null ? PathUtil.Normalize(dll) : PathUtil.ResolveCommandLine(image).Executable;
        if (file != null && File.Exists(file) && FileTrustService.Shared.Get(file).IsWindowsComponent)
            return "Dienst einer verifizierten Windows-Komponente – wird nicht deaktiviert.";
        return null;
    }
}
