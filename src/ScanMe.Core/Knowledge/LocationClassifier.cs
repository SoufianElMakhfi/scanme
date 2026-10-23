using ScanMe.Core.Util;

namespace ScanMe.Core.Knowledge;

public enum LocationKind
{
    WindowsSystem,
    Windows,
    ProgramFiles,
    ProgramData,
    UserAppDataRoaming,
    UserAppDataLocal,
    UserAppDataLocalPrograms,
    Temp,
    Downloads,
    Desktop,
    Public,
    RecycleBin,
    Other,
}

/// <summary>
/// Bewertet, wie verdaechtig ein Speicherort fuer ausfuehrbaren Code ist.
/// Malware legt sich bevorzugt in benutzerbeschreibbare Ordner (Temp, AppData, Public, Papierkorb).
/// </summary>
public static class LocationClassifier
{
    public static LocationKind Classify(string? path)
    {
        if (string.IsNullOrEmpty(path)) return LocationKind.Other;
        string p = path;

        if (p.Contains(@"\$Recycle.Bin\", StringComparison.OrdinalIgnoreCase)) return LocationKind.RecycleBin;
        if (p.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase)
            || PathUtil.IsUnder(p, Path.Combine(PathUtil.WindowsDir, "Temp"))
            || PathUtil.IsUnder(p, Path.GetTempPath()))
            return LocationKind.Temp;
        if (PathUtil.IsInSystemDirectory(p)) return LocationKind.WindowsSystem;
        if (PathUtil.IsUnderWindowsDirectory(p)) return LocationKind.Windows;
        if (PathUtil.IsUnderProgramFiles(p)) return LocationKind.ProgramFiles;
        if (PathUtil.IsUnder(p, PathUtil.ProgramData)) return LocationKind.ProgramData;
        if (PathUtil.IsUnder(p, Path.Combine(PathUtil.UsersRoot, "Public"))) return LocationKind.Public;
        if (p.Contains(@"\AppData\Roaming\", StringComparison.OrdinalIgnoreCase)) return LocationKind.UserAppDataRoaming;
        if (p.Contains(@"\AppData\Local\Programs\", StringComparison.OrdinalIgnoreCase)
            || p.Contains(@"\AppData\Local\Microsoft\WindowsApps\", StringComparison.OrdinalIgnoreCase))
            return LocationKind.UserAppDataLocalPrograms;
        if (p.Contains(@"\AppData\Local\", StringComparison.OrdinalIgnoreCase)) return LocationKind.UserAppDataLocal;
        if (p.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase)) return LocationKind.Downloads;
        if (p.Contains(@"\Desktop\", StringComparison.OrdinalIgnoreCase)) return LocationKind.Desktop;
        if (p.StartsWith(@"C:\PerfLogs\", StringComparison.OrdinalIgnoreCase)) return LocationKind.Temp;
        return LocationKind.Other;
    }

    /// <summary>Risikogewicht fuer ausfuehrbaren Code an diesem Ort.</summary>
    public static int Weight(LocationKind k) => k switch
    {
        LocationKind.RecycleBin => 40,
        LocationKind.Temp => 30,
        LocationKind.Public => 30,
        LocationKind.Downloads => 15,
        LocationKind.Desktop => 15,
        LocationKind.UserAppDataRoaming => 15,
        LocationKind.ProgramData => 10,
        LocationKind.UserAppDataLocal => 10,
        LocationKind.UserAppDataLocalPrograms => 3,
        LocationKind.Other => 8,
        _ => 0,
    };

    public static string Describe(LocationKind k) => k switch
    {
        LocationKind.RecycleBin => "läuft aus dem Papierkorb – ein klassisches Malware-Versteck",
        LocationKind.Temp => "liegt in einem temporären Ordner – legitime Programme laufen dort selten dauerhaft",
        LocationKind.Public => "liegt im oeffentlichen Benutzerordner (C:\\Users\\Public) – beliebtes Malware-Versteck",
        LocationKind.Downloads => "wird direkt aus dem Download-Ordner ausgeführt",
        LocationKind.Desktop => "wird direkt vom Desktop ausgeführt",
        LocationKind.UserAppDataRoaming => "liegt in AppData\\Roaming – von jedem Programm ohne Adminrechte beschreibbar",
        LocationKind.ProgramData => "liegt in ProgramData – von Benutzern beschreibbar",
        LocationKind.UserAppDataLocal => "liegt in AppData\\Local – ohne Adminrechte beschreibbar",
        LocationKind.UserAppDataLocalPrograms => "ist eine pro Benutzer installierte Anwendung",
        LocationKind.Other => "liegt an einem ungewöhnlichen Ort",
        LocationKind.ProgramFiles => "ist regulär unter Programme installiert",
        _ => "liegt im Windows-Verzeichnis",
    };

    public static bool IsUserWritable(LocationKind k) => Weight(k) >= 10;
}
