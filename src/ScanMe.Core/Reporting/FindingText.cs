using System.Text;
using ScanMe.Core.Models;

namespace ScanMe.Core.Reporting;

/// <summary>Ein Fund als Klartext – zum Kopieren und Weitergeben (z. B. an einen Helfer oder in ein Forum).</summary>
public static class FindingText
{
    /// <summary>Pruefungen in fester Reihenfolge: Virenschutz zuerst, dann YARA, dann Signatur.</summary>
    public static IEnumerable<Check> Ordered(IEnumerable<Check> checks) =>
        checks.OrderBy(c => c.IsAntivirus ? 0 : c.Source == Check.Yara ? 1 : 2);

    public static string ToText(Finding f)
    {
        var sb = new StringBuilder();
        sb.AppendLine(f.Title);
        sb.AppendLine($"Einschätzung: {f.Verdict.German()} · {f.Category.German()} · technisch {f.Severity.German()} (Score {f.Score})");
        if ((f.FilePath ?? f.Location) is { } where) sb.AppendLine($"Ort: {where}");
        if (f.OccurredAt is { } t) sb.AppendLine($"{f.OccurredWhat}: {(f.OccurredDayOnly ? t.ToString("d") : t.ToString("g"))}");

        Section(sb, "Unsere Einschätzung", f.PlainSummary);
        if (f.Certainty.Length > 0 || f.Checks.Count > 0)
        {
            Heading(sb, "Wie sicher ist das?");
            if (f.Certainty.Length > 0) sb.AppendLine(f.Certainty);
            foreach (var c in Ordered(f.Checks)) sb.AppendLine($"  {c.Symbol} {c.Source}: {c.Text}");
        }
        if (f.Questions.Count > 0)
        {
            Heading(sb, "Nur Sie können das beantworten");
            foreach (var q in f.Questions) sb.AppendLine($"  ? {q}");
        }
        Section(sb, "Wenn Sie es nicht kennen", f.IfUnknown);
        Section(sb, "Was wurde gefunden", f.Description);
        Section(sb, "Hintergrund", f.Explanation);
        Section(sb, "Empfehlung", f.Recommendation);

        var indicators = f.Indicators.Where(i => i.Weight != 0).OrderByDescending(i => i.Weight).ToList();
        if (indicators.Count > 0)
        {
            Heading(sb, "Indikatoren (+ erhöht, − senkt das Risiko)");
            foreach (var i in indicators) sb.AppendLine($"  {(i.Weight > 0 ? "+" : "")}{i.Weight,3}  {i.Text}");
        }
        if (f.Details.Count > 0)
        {
            Heading(sb, "Technische Details");
            foreach (var d in f.Details)
                sb.AppendLine($"  {d.Key}: {d.Value.ReplaceLineEndings(Environment.NewLine + "    ")}");
        }
        return sb.ToString().TrimEnd();
    }

    private static void Heading(StringBuilder sb, string heading)
    {
        sb.AppendLine();
        sb.AppendLine(heading.ToUpperInvariant());
    }

    private static void Section(StringBuilder sb, string heading, string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        Heading(sb, heading);
        sb.AppendLine(text);
    }
}
