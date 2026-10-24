using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ScanMe.Core.Actions;
using ScanMe.Core.Trust;
using ScanMe.Core.Util;

namespace ScanMe.Core.Telemetry;

/// <summary>
/// Installiert Microsoft Sysmon (Sysinternals) mit der ScanMe-Konfiguration.
/// Sysmon wird direkt von Microsoft geladen und nur gestartet, wenn die Microsoft-Signatur gueltig ist.
/// </summary>
public static class SysmonService
{
    public const string DownloadUrl = "https://download.sysinternals.com/files/Sysmon.zip";

    private static string Dir => Path.Combine(AppPaths.DataDir, "Sysmon");
    private static string ConfigPath => Path.Combine(Dir, "scanme-sysmon.xml");
    /// <summary>Merker: Sysmon wurde von ScanMe installiert (nur dann deinstalliert ScanMe es auch wieder).</summary>
    private static string InstalledMarker => Path.Combine(Dir, "installed-by-scanme.txt");

    private static string ExeName => RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "Sysmon64a.exe" : "Sysmon64.exe";
    private static string ServiceName => Path.GetFileNameWithoutExtension(ExeName);

    public static bool IsInstalled() =>
        new[] { "Sysmon64", "Sysmon64a", "Sysmon" }.Any(s => RegistryUtil.Open($@"HKLM\SYSTEM\CurrentControlSet\Services\{s}") is { } k && Dispose(k));

    public static bool InstalledByScanMe => File.Exists(InstalledMarker);

    /// <summary>Aktuelle Konfiguration bereits angewendet?</summary>
    public static bool ConfigCurrent() =>
        File.Exists(InstalledMarker) && File.ReadAllText(InstalledMarker).Trim() == ConfigHash();

    private static string ConfigHash() => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(SysmonConfig.Build())))[..16];

    /// <summary>Installiert bzw. aktualisiert die Konfiguration. Rueckgabe: Fehlermeldung oder null.</summary>
    public static string? Install()
    {
        Directory.CreateDirectory(Dir);
        File.WriteAllText(ConfigPath, SysmonConfig.Build(), new UTF8Encoding(false));

        if (IsInstalled())
        {
            // Fremde Installation (z. B. Firmen-IT) nicht ueberschreiben.
            if (!InstalledByScanMe) return null;
            var installed = Path.Combine(PathUtil.WindowsDir, ExeName);
            if (!File.Exists(installed) || !FileTrustService.Shared.Get(installed).IsMicrosoftSigned)
                return "Die installierte Sysmon-Datei ist nicht von Microsoft signiert – bitte prüfen.";
            var (rc, output) = ActionExecutor.RunTool(installed, $"-c \"{ConfigPath}\"");
            if (rc != 0) return "Sysmon-Konfiguration fehlgeschlagen: " + output.Trim();
            File.WriteAllText(InstalledMarker, ConfigHash());
            return null;
        }

        string exe;
        try { exe = Download(); }
        catch (Exception ex) { return "Download von Microsoft fehlgeschlagen: " + ex.Message; }

        var trust = FileTrustService.Shared.Get(exe);
        if (!trust.IsMicrosoftSigned)
            return $"Abgebrochen: Die heruntergeladene Datei ist nicht gültig von Microsoft signiert ({trust.SignatureStatusText}).";

        // Reste eines abgebrochenen Versuchs (Programm/Ereignisquelle ohne Dienst) lassen die Neuinstallation
        // mit "Event manifest installation failed" scheitern – vorher vollstaendig entfernen.
        if (File.Exists(Path.Combine(PathUtil.WindowsDir, ExeName)))
            ActionExecutor.RunTool(exe, "-u force");

        var (code, text) = ActionExecutor.RunTool(exe, $"-accepteula -i \"{ConfigPath}\"");
        if (code != 0)
        {
            ActionExecutor.RunTool(exe, "-u force"); // keinen halb installierten Zustand zuruecklassen
            return "Sysmon-Installation fehlgeschlagen: " + text.Trim();
        }
        File.WriteAllText(InstalledMarker, ConfigHash());

        // Grosses Protokoll: Herkunft bleibt wochenlang nachvollziehbar.
        ActionExecutor.RunTool("wevtutil.exe", $"sl \"{Provenance.SysmonLog}\" /ms:268435456");
        return null;
    }

    public static string? Uninstall()
    {
        if (!IsInstalled()) return null;
        if (!InstalledByScanMe) return "Sysmon wurde nicht von ScanMe installiert (z. B. von Ihrer IT) und wird daher nicht entfernt.";
        var installed = Path.Combine(PathUtil.WindowsDir, ExeName);
        if (!File.Exists(installed)) return "Sysmon-Programm nicht gefunden.";
        if (!FileTrustService.Shared.Get(installed).IsMicrosoftSigned) return "Die installierte Sysmon-Datei ist nicht von Microsoft signiert – bitte prüfen.";
        var (code, output) = ActionExecutor.RunTool(installed, "-u");
        if (code != 0) return "Deinstallation fehlgeschlagen: " + output.Trim();
        try { File.Delete(InstalledMarker); } catch { }
        return null;
    }

    private static string Download()
    {
        var target = Path.Combine(Dir, "download");
        if (Directory.Exists(target)) Directory.Delete(target, recursive: true);
        Directory.CreateDirectory(target);
        var zip = Path.Combine(target, "Sysmon.zip");

        using (var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) })
        {
            http.DefaultRequestHeaders.UserAgent.ParseAdd("ScanMe");
            var bytes = http.GetByteArrayAsync(DownloadUrl).GetAwaiter().GetResult();
            File.WriteAllBytes(zip, bytes);
        }
        // Nur die benoetigte Datei entpacken – keine Pfade aus dem Archiv uebernehmen.
        using var archive = ZipFile.OpenRead(zip);
        var entry = archive.Entries.FirstOrDefault(e => e.Name.Equals(ExeName, StringComparison.OrdinalIgnoreCase))
                    ?? throw new InvalidDataException($"{ExeName} nicht im Archiv");
        var exe = Path.Combine(target, ExeName);
        entry.ExtractToFile(exe, overwrite: true);
        return exe;
    }

    private static bool Dispose(IDisposable d) { d.Dispose(); return true; }
}
