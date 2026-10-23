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

    /// <summary>Stabiler Schluessel zum Wiedererkennen (Ignorierliste, Vergleich zwischen Scans).</summary>
    public string Fingerprint => $"{ScannerId}|{Title}|{FilePath ?? Location}".ToLowerInvariant();

    public Finding AddIndicator(string code, string text, int weight)
    {
        if (!Indicators.Any(i => i.Code == code))
            Indicators.Add(new Indicator(code, text, weight));
        return this;
    }

    public Finding Detail(string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            Details[key] = value;
        return this;
    }
}
