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
        FindingCategory.Compatibility => "Kompatibilitaet & Stabilitaet",
        _ => c.ToString(),
    };
}
