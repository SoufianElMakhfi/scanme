namespace ScanMe.Core.Models;

public sealed class Finding
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public required string ScannerId { get; init; }
    public required FindingCategory Category { get; set; }
    public required string Title { get; init; }

    /// <summary>Was wurde gefunden.</summary>
    public string Description { get; set; } = "";

    /// <summary>Warum ist das relevant / was bedeutet es.</summary>
    public string Explanation { get; set; } = "";

    /// <summary>Was soll der Benutzer tun.</summary>
    public string Recommendation { get; set; } = "";

    public Severity Severity { get; set; }
    public int Score { get; set; }

    // --- Laienverstaendliche Einschaetzung (siehe Engine/PlainLanguage) ---

    /// <summary>Ampel fuer Nicht-Experten.</summary>
    public Verdict Verdict { get; set; }

    /// <summary>Ein bis zwei Saetze ohne Fachbegriffe: Was heisst das fuer mich?</summary>
    public string PlainSummary { get; set; } = "";

    /// <summary>Ja/Nein-Fragen, die nur der Nutzer beantworten kann (z. B. "Kennen Sie dieses Programm?").</summary>
    public List<string> Questions { get; } = new();

    /// <summary>Was tun, wenn der Nutzer das NICHT kennt – ein konkreter Schritt.</summary>
    public string IfUnknown { get; set; } = "";

    public string? FilePath { get; set; }
    public int? ProcessId { get; set; }
    public string? Location { get; set; }
    public string? Sha256 { get; set; }

    /// <summary>Windows-Komponente oder kritischer Systemprozess: darf nie geloescht/beendet werden.</summary>
    public bool IsProtected { get; set; }

    public List<Indicator> Indicators { get; } = new();
    public Dictionary<string, string> Details { get; } = new();
    public List<RemediationAction> Actions { get; } = new();

    public DateTime DetectedAt { get; init; } = DateTime.Now;

    // --- Zeitleiste: wann das Gefundene tatsaechlich passiert ist (nicht wann gescannt wurde) ---

    public DateTime? OccurredAt { get; set; }

    /// <summary>Was zu diesem Zeitpunkt geschah, z. B. "Datei erstellt" oder "Dienst installiert".</summary>
    public string? OccurredWhat { get; set; }

    /// <summary>Nur das Datum ist bekannt (z. B. Installationsdatum aus der Registry), keine Uhrzeit.</summary>
    public bool OccurredDayOnly { get; set; }

    /// <summary>Stabiler Schluessel zum Wiedererkennen (Ignorierliste, Vergleich zwischen Scans).</summary>
    public string Fingerprint => $"{ScannerId}|{Title}|{FilePath ?? Location}".ToLowerInvariant();

    public Finding AddIndicator(string code, string text, int weight)
    {
        if (!Indicators.Any(i => i.Code == code))
            Indicators.Add(new Indicator(code, text, weight));
        return this;
    }

    /// <summary>Setzt den Ereigniszeitpunkt; unplausible Werte (leer, vor 1990, Zukunft) werden ignoriert.</summary>
    public Finding At(DateTime? when, string what, bool dayOnly = false)
    {
        if (when is not { } w || w.Year < 1990 || w > DateTime.Now.AddDays(1)) return this;
        OccurredAt = w;
        OccurredWhat = what;
        OccurredDayOnly = dayOnly;
        return this;
    }

    public Finding Detail(string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            Details[key] = value;
        return this;
    }
}
