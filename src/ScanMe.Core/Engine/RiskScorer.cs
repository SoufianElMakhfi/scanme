using ScanMe.Core.Models;

namespace ScanMe.Core.Engine;

/// <summary>Berechnet aus den Indikatoren eines Fundes Score (0–100) und Schweregrad.</summary>
public static class RiskScorer
{
    public static void Finalize(Finding f)
    {
        int score = Math.Clamp(f.Indicators.Sum(i => i.Weight), 0, 100);

        // Verifizierte Windows-Komponenten werden nie hoeher als "Niedrig" eingestuft,
        // solange kein harter Missbrauchsindikator (z. B. boesartige Kommandozeile) vorliegt.
        bool hardEvidence = f.Indicators.Any(i => i.Weight >= 45);
        if (f.IsProtected && !hardEvidence) score = Math.Min(score, 20);

        f.Score = score;
        f.Severity = FromScore(score);
    }

    public static Severity FromScore(int score) => score switch
    {
        >= 80 => Severity.Critical,
        >= 60 => Severity.High,
        >= 35 => Severity.Medium,
        >= 15 => Severity.Low,
        _ => Severity.Info,
    };

    /// <summary>Basis-Indikator, damit ein Fund mit festem Schweregrad gemeldet werden kann.</summary>
    public static int BaseWeight(Severity s) => s switch
    {
        Severity.Critical => 85,
        Severity.High => 65,
        Severity.Medium => 40,
        Severity.Low => 20,
        _ => 0,
    };
}
