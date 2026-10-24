using ScanMe.Core.Models;

namespace ScanMe.Core.Engine;

/// <summary>Ein Fund an seinem Ereigniszeitpunkt. <see cref="Cluster"/> = 0: gehoert zu keiner Haeufung.</summary>
public sealed record TimelineEntry(Finding Finding, int Cluster);

/// <summary>Zeitlich zusammenhaengende auffaellige Ereignisse, z. B. Download → PowerShell → neuer Autostart.</summary>
public sealed record TimelineCluster(int Id, DateTime From, DateTime To, int NotableCount);

public sealed record TimelineResult(List<TimelineEntry> Entries, List<TimelineCluster> Clusters);

/// <summary>
/// Ordnet Funde nach dem Zeitpunkt, zu dem das Gefundene passiert ist, und markiert Haeufungen.
/// Ein Angriff hinterlaesst typischerweise mehrere Spuren innerhalb weniger Minuten – einzeln wirken sie harmlos.
/// </summary>
public static class Timeline
{
    /// <summary>Hoechstens so viel Zeit zwischen zwei Ereignissen derselben Haeufung.</summary>
    public static readonly TimeSpan ClusterGap = TimeSpan.FromMinutes(10);

    /// <summary>Neueste zuerst. Funde ohne Zeitpunkt fehlen; Funde nur mit Datum zaehlen fuer keine Haeufung.</summary>
    public static TimelineResult Build(IEnumerable<Finding> findings)
    {
        var timed = findings.Where(f => f.OccurredAt != null).OrderBy(f => f.OccurredAt).ToList();
        var clusterOf = new Dictionary<Finding, int>();
        var clusters = new List<TimelineCluster>();

        var group = new List<Finding>();
        void Close()
        {
            // Erst ab zwei auffaelligen Ereignissen; harmlose Ereignisse im selben Zeitraum gehoeren als Kontext dazu.
            int notable = group.Count(IsNotable);
            if (notable >= 2)
            {
                var c = new TimelineCluster(clusters.Count + 1, group[0].OccurredAt!.Value, group[^1].OccurredAt!.Value, notable);
                clusters.Add(c);
                foreach (var f in group) clusterOf[f] = c.Id;
            }
            group.Clear();
        }

        foreach (var f in timed.Where(f => !f.OccurredDayOnly))
        {
            if (group.Count > 0 && f.OccurredAt!.Value - group[^1].OccurredAt!.Value > ClusterGap) Close();
            group.Add(f);
        }
        Close();

        var entries = timed
            .OrderByDescending(f => f.OccurredAt)
            .ThenByDescending(f => f.Verdict)
            .Select(f => new TimelineEntry(f, clusterOf.GetValueOrDefault(f)))
            .ToList();
        return new TimelineResult(entries, clusters);
    }

    public static bool IsNotable(Finding f) => f.Verdict >= Verdict.Check;
}
