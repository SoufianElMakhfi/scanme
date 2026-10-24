using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using ScanMe.Core.Actions;

namespace ScanMe.Core.Hardening;

/// <summary>Ein Eintrag aus dem Testmodus: "Das waere blockiert worden".</summary>
public sealed record AuditHit(DateTime When, string Rule, string Process, string Target, bool Blocked);

public static class HardeningService
{
    /// <summary>Setzt eine Massnahme und speichert den vorherigen Zustand fuer "Rueckgaengig".</summary>
    public static ActionResult Apply(HardeningItem item, HardeningMode mode)
    {
        var before = item.Read();
        string? error = item.Apply(mode);
        if (error != null) return ActionResult.Fail($"{item.Title}: {error}");

        UndoJournal.Add(new UndoEntry
        {
            Kind = UndoKind.Hardening,
            Target = item.Id,
            PreviousValue = before.ToString(),
            Description = $"Schutz „{item.Title}“: {Text(before)} → {Text(mode)}",
        });
        return ActionResult.Ok(item.NeedsReboot ? $"{item.Title}: {Text(mode)} – wirkt nach dem nächsten Neustart." : $"{item.Title}: {Text(mode)}.");
    }

    public static List<ActionResult> ApplyRecommended() =>
        HardeningCatalog.All
            .Where(i => i.Recommended != null)
            .Where(i => i.Read() is not HardeningState.NotAvailable)
            .Where(i => !Satisfies(i.Read(), i.Recommended!.Value))
            .Select(i => Apply(i, i.Recommended!.Value))
            .ToList();

    /// <summary>Ist der aktuelle Zustand mindestens so streng wie gewuenscht?</summary>
    public static bool Satisfies(HardeningState state, HardeningMode wanted) => wanted switch
    {
        HardeningMode.On => state == HardeningState.On,
        HardeningMode.Audit => state is HardeningState.Audit or HardeningState.On,
        _ => true,
    };

    public static string Text(HardeningState s) => s switch
    {
        HardeningState.On => "aktiv",
        HardeningState.Audit => "Testmodus",
        HardeningState.Off => "aus",
        HardeningState.NotAvailable => "nicht vorhanden",
        _ => "unbekannt",
    };

    public static string Text(HardeningMode m) => m switch
    {
        HardeningMode.On => "aktiv",
        HardeningMode.Audit => "Testmodus",
        _ => "aus",
    };

    /// <summary>Stellt den vorherigen Zustand wieder her (vom Rueckgaengig-Journal genutzt).</summary>
    internal static string? Restore(string id, string? previous)
    {
        var item = HardeningCatalog.All.FirstOrDefault(i => i.Id == id);
        if (item == null) return "Unbekannte Schutzmaßnahme.";
        var mode = Enum.TryParse<HardeningState>(previous, out var s) ? s switch
        {
            HardeningState.On => HardeningMode.On,
            HardeningState.Audit => HardeningMode.Audit,
            _ => HardeningMode.Off,
        } : HardeningMode.Off;
        return item.Apply(mode);
    }

    /// <summary>
    /// Was haben die Schutzregeln im Testmodus (bzw. scharf) protokolliert? Defender-Ereignisse:
    /// 1121/1122 ASR blockiert/Test, 1123/1124 Ordnerschutz, 1125/1126 Netzwerkschutz.
    /// </summary>
    public static List<AuditHit> RecentHits(int days = 14)
    {
        var hits = new List<AuditHit>();
        long ms = days * 24L * 3600 * 1000;
        string xpath = $"*[System[(EventID=1121 or EventID=1122 or EventID=1123 or EventID=1124 or EventID=1125 or EventID=1126) and TimeCreated[timediff(@SystemTime) <= {ms}]]]";
        try
        {
            using var reader = new EventLogReader(new EventLogQuery("Microsoft-Windows-Windows Defender/Operational", PathType.LogName, xpath) { ReverseDirection = true });
            for (int n = 0; n < 500; n++)
            {
                using var r = reader.ReadEvent();
                if (r == null) break;
                var data = XDocument.Parse(r.ToXml()).Descendants().Where(e => e.Name.LocalName == "Data")
                    .ToDictionary(e => (string?)e.Attribute("Name") ?? "", e => e.Value, StringComparer.OrdinalIgnoreCase);
                string rule = r.Id is 1123 or 1124 ? "Überwachter Ordnerzugriff"
                    : r.Id is 1125 or 1126 ? "Netzwerkschutz"
                    : RuleName(data.GetValueOrDefault("ID"));
                hits.Add(new AuditHit(r.TimeCreated ?? DateTime.MinValue, rule,
                    data.GetValueOrDefault("Process Name") ?? "?", data.GetValueOrDefault("Path") ?? "",
                    r.Id is 1121 or 1123 or 1126));
            }
        }
        catch { /* Protokoll nicht lesbar */ }
        return hits;
    }

    private static string RuleName(string? id)
    {
        if (id == null) return "Defender-Regel";
        var item = HardeningCatalog.All.FirstOrDefault(i => i.Id.Equals("asr:" + id.Trim('{', '}'), StringComparison.OrdinalIgnoreCase));
        return item?.Title ?? $"Defender-Regel {id}";
    }
}
