namespace ScanMe.Core.Models;

public sealed class ScannerResult
{
    public required string ScannerId { get; init; }
    public required string ScannerName { get; init; }
    public TimeSpan Duration { get; set; }
    public int FindingCount { get; set; }
    public string? Error { get; set; }
    public List<string> Notes { get; } = new();
}

public sealed class ScanReport
{
    public DateTime StartedAt { get; init; } = DateTime.Now;
    public DateTime FinishedAt { get; set; }
    public string MachineName { get; init; } = Environment.MachineName;
    public string UserName { get; init; } = Environment.UserName;
    public string OsVersion { get; set; } = "";
    public bool WasElevated { get; set; }
    public bool Cancelled { get; set; }

    public List<Finding> Findings { get; } = new();
    public List<ScannerResult> ScannerResults { get; } = new();

    public int Count(Severity s) => Findings.Count(f => f.Severity == s);

    /// <summary>0 (kompromittiert) bis 100 (sauber).</summary>
    public int HealthScore
    {
        get
        {
            double penalty = Findings.Sum(f => f.Severity switch
            {
                Severity.Critical => 25.0,
                Severity.High => 10.0,
                Severity.Medium => 3.0,
                Severity.Low => 0.5,
                _ => 0.0,
            });
            return Math.Clamp(100 - (int)Math.Round(penalty), 0, 100);
        }
    }
}

public sealed record ScanProgress(string ScannerName, int ScannerIndex, int ScannerCount, string Message);
