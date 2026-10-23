namespace ScanMe.Core.Models;

/// <summary>
/// Ein einzelnes Beweisstueck, das zur Risikobewertung eines Fundes beitraegt.
/// Negative Gewichte senken das Risiko (z. B. gueltige Microsoft-Signatur).
/// </summary>
public sealed record Indicator(string Code, string Text, int Weight);
