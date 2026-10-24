namespace ScanMe.Core.Models;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public enum FindingCategory
{
    Process,
    Persistence,
    Network,
    FileSystem,
    Malware,
    SecurityConfig,
    Browser,
    EventLog,
    Driver,
    Account,
    Compatibility,
}

/// <summary>Einfache Ampel fuer Laien – unabhaengig vom technischen Score.</summary>
public enum Verdict
{
    /// <summary>Nur zur Information, nichts zu tun.</summary>
    Info,
    /// <summary>Nur schwache Hinweise (z. B. fehlende Signatur) – meist harmlos.</summary>
    LikelyHarmless,
    /// <summary>Kurz pruefen: Nur Sie wissen, ob das gewollt ist.</summary>
    Check,
    /// <summary>Harte Beweise fuer Schadsoftware oder Angriff – handeln.</summary>
    Act,
}

public static class SeverityText
{
    public static string German(this Severity s) => s switch
    {
        Severity.Critical => "Kritisch",
        Severity.High => "Hoch",
        Severity.Medium => "Mittel",
        Severity.Low => "Niedrig",
        _ => "Info",
    };

    public static string German(this FindingCategory c) => c switch
    {
        FindingCategory.Process => "Prozesse",
        FindingCategory.Persistence => "Autostart & Persistenz",
        FindingCategory.Network => "Netzwerk",
        FindingCategory.FileSystem => "Dateisystem",
        FindingCategory.Malware => "Malware",
        FindingCategory.SecurityConfig => "Sicherheitseinstellungen",
        FindingCategory.Browser => "Browser",
        FindingCategory.EventLog => "Ereignisprotokolle",
        FindingCategory.Driver => "Treiber",
        FindingCategory.Account => "Benutzerkonten",
        FindingCategory.Compatibility => "Kompatibilität & Stabilität",
        _ => c.ToString(),
    };
}
