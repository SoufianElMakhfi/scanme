using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ScanMe.Core.Models;

namespace ScanMe.Core.Reporting;

/// <summary>Exportiert einen Scan als eigenstaendige HTML-Datei (zum Weitergeben, z. B. an einen Experten) oder als JSON.</summary>
public static class ReportWriter
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

    public static string ToJson(ScanReport report) => JsonSerializer.Serialize(report, Json);

    public static string ToHtml(ScanReport report, IEnumerable<Finding>? findings = null)
    {
        var list = (findings ?? report.Findings).ToList();
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        static string Color(Severity s) => s switch
        {
            Severity.Critical => "#E5484D", Severity.High => "#F2762E", Severity.Medium => "#D9A400", Severity.Low => "#4C8DFF", _ => "#7C8598",
        };

        var sb = new StringBuilder();
        sb.Append("""
            <!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>ScanMe Bericht</title>
            <style>
            :root{--bg:#fff;--fg:#1b1f27;--muted:#5d6577;--card:#f5f7fa;--border:#e1e5ec}
            @media (prefers-color-scheme:dark){:root{--bg:#0e1116;--fg:#e7eaf0;--muted:#97a0b3;--card:#151922;--border:#2c3342}}
            body{background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",system-ui,sans-serif;margin:0;padding:24px;max-width:1100px;margin:auto}
            h1{margin:0 0 4px;font-size:26px} .muted{color:var(--muted)}
            .stats{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}
            .stat{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 16px;min-width:110px}
            .stat b{font-size:22px;display:block}
            .f{background:var(--card);border:1px solid var(--border);border-left:5px solid;border-radius:10px;padding:14px 16px;margin:10px 0}
            .f h3{margin:0 0 6px;font-size:15px} .badge{color:#fff;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:600;margin-right:6px}
            .ind{font-family:Consolas,monospace;font-size:12px;margin:2px 0} .pos{color:#d9534f} .neg{color:#2fbf71}
            details{margin-top:6px} table{border-collapse:collapse;font-size:12px;width:100%} td{border-top:1px solid var(--border);padding:3px 6px;vertical-align:top;word-break:break-all}
            td:first-child{white-space:nowrap;color:var(--muted);width:160px} .rec{margin-top:6px} code{font-family:Consolas,monospace}
            </style></head><body>
            """);
        sb.Append($"<h1>ScanMe – Sicherheitsbericht</h1><div class='muted'>{E(report.MachineName)} · {E(report.OsVersion)} · {report.StartedAt:dd.MM.yyyy HH:mm} · " +
                  $"{(report.WasElevated ? "mit Adminrechten" : "ohne Adminrechte (eingeschränkt)")}</div>");
        sb.Append("<div class='stats'>");
        sb.Append($"<div class='stat'><span class='muted'>Gesundheit</span><b>{report.HealthScore}/100</b></div>");
        foreach (var s in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
            sb.Append($"<div class='stat'><span class='muted'>{s.German()}</span><b style='color:{Color(s)}'>{list.Count(f => f.Severity == s)}</b></div>");
        sb.Append("</div>");

        // Zeitleiste der auffaelligen Funde â€“ fuer Helfer oft der schnellste Weg, den Ablauf zu verstehen.
        var timeline = Engine.Timeline.Build(list.Where(Engine.Timeline.IsNotable));
        if (timeline.Entries.Count > 0)
        {
            sb.Append("<h2>Zeitleiste (auffÃ¤llige Funde)</h2><table>");
            foreach (var e in timeline.Entries.Take(100))
            {
                var t = e.Finding.OccurredAt!.Value;
                sb.Append($"<tr><td>{(e.Finding.OccurredDayOnly ? t.ToString("dd.MM.yyyy") : t.ToString("dd.MM.yyyy HH:mm"))}{(e.Cluster != 0 ? $" <b style='color:#F2762E'>âš  HÃ¤ufung {e.Cluster}</b>" : "")}</td>" +
                          $"<td>{E(e.Finding.Title)} <span class='muted'>Â· {E(e.Finding.OccurredWhat ?? "")}</span></td></tr>");
            }
            sb.Append("</table>");
        }

        foreach (var group in list.Where(f => f.Severity >= Severity.Low).GroupBy(f => f.Category).OrderByDescending(g => g.Max(f => f.Score)))
        {
            sb.Append($"<h2>{E(group.Key.German())}</h2>");
            foreach (var f in group.OrderByDescending(f => f.Score))
            {
                sb.Append($"<div class='f' style='border-left-color:{Color(f.Severity)}'>");
                sb.Append($"<h3><span class='badge' style='background:{Color(f.Severity)}'>{E(f.Severity.German())} {f.Score}</span>{E(f.Title)}</h3>");
                if (f.OccurredAt is { } when)
                    sb.Append($"<div class='muted'>{E(f.OccurredWhat ?? "")}: {(f.OccurredDayOnly ? when.ToString("dd.MM.yyyy") : when.ToString("dd.MM.yyyy HH:mm"))}</div>");
                if (f.Description.Length > 0) sb.Append($"<div>{E(f.Description)}</div>");
                if (f.Explanation.Length > 0) sb.Append($"<div class='muted'>{E(f.Explanation)}</div>");
                if (f.Recommendation.Length > 0) sb.Append($"<div class='rec'><b>Empfehlung:</b> {E(f.Recommendation)}</div>");
                sb.Append("<details><summary>Indikatoren &amp; Details</summary>");
                foreach (var i in f.Indicators.Where(i => i.Weight != 0).OrderByDescending(i => i.Weight))
                    sb.Append($"<div class='ind {(i.Weight > 0 ? "pos" : "neg")}'>{(i.Weight > 0 ? "+" : "")}{i.Weight} {E(i.Text)}</div>");
                sb.Append("<table>");
                foreach (var d in f.Details) sb.Append($"<tr><td>{E(d.Key)}</td><td>{E(d.Value)}</td></tr>");
                sb.Append("</table></details></div>");
            }
        }

        sb.Append("<h2>Scanner</h2><table>");
        foreach (var r in report.ScannerResults)
            sb.Append($"<tr><td>{E(r.ScannerName)}</td><td>{r.Duration.TotalSeconds:0.0}s · {r.FindingCount} Funde{(r.Error != null ? " · Fehler: " + E(r.Error) : "")}" +
                      $"{string.Concat(r.Notes.Select(n => "<br><span class='muted'>" + E(n) + "</span>"))}</td></tr>");
        sb.Append("</table><p class='muted'>Erstellt mit ScanMe. Dieser Bericht enthält Dateipfade und Benutzernamen dieses PCs – nur an vertrauenswürdige Personen weitergeben.</p></body></html>");
        return sb.ToString();
    }
}
