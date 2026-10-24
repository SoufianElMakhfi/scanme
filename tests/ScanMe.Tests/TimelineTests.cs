using ScanMe.Core.Engine;
using ScanMe.Core.Models;

namespace ScanMe.Tests;

/// <summary>Die Zeitleiste soll zusammenhaengende Angriffsspuren hervorheben, aber keine Haeufung aus Harmlosem bilden.</summary>
public class TimelineTests
{
    private static readonly DateTime T0 = new(2026, 3, 14, 14, 0, 0);

    private static Finding Make(string title, Verdict verdict, DateTime? when, bool dayOnly = false)
    {
        var f = new Finding { ScannerId = "test", Category = FindingCategory.FileSystem, Title = title, Verdict = verdict };
        f.At(when, "Test", dayOnly);
        return f;
    }

    [Fact]
    public void NewestFirst_AndUntimedLeftOut()
    {
        var result = Timeline.Build([
            Make("alt", Verdict.Check, T0),
            Make("neu", Verdict.Check, T0.AddDays(2)),
            Make("ohne Zeit", Verdict.Act, null),
        ]);
        Assert.Equal(["neu", "alt"], result.Entries.Select(e => e.Finding.Title));
    }

    [Fact]
    public void AttackChain_WithinMinutes_IsOneCluster()
    {
        var download = Make("Download", Verdict.Check, T0);
        var powershell = Make("PowerShell", Verdict.Act, T0.AddMinutes(1));
        var context = Make("Unsigniertes Hilfsprogramm", Verdict.LikelyHarmless, T0.AddMinutes(2));
        var autostart = Make("Autostart", Verdict.Check, T0.AddMinutes(8));
        var later = Make("Viel später", Verdict.Check, T0.AddHours(3));

        var result = Timeline.Build([download, powershell, context, autostart, later]);

        var cluster = Assert.Single(result.Clusters);
        Assert.Equal(3, cluster.NotableCount);
        Assert.Equal(T0, cluster.From);
        Assert.Equal(T0.AddMinutes(8), cluster.To);
        int Id(Finding f) => result.Entries.Single(e => e.Finding == f).Cluster;
        Assert.All(new[] { download, powershell, context, autostart }, f => Assert.Equal(cluster.Id, Id(f)));
        Assert.Equal(0, Id(later));
    }

    [Fact]
    public void HarmlessOnly_IsNoCluster()
    {
        // Typisch fuer eine normale Programminstallation oder den Systemstart
        var result = Timeline.Build([
            Make("a", Verdict.LikelyHarmless, T0),
            Make("b", Verdict.Info, T0.AddMinutes(1)),
            Make("c", Verdict.Check, T0.AddMinutes(2)),
        ]);
        Assert.Empty(result.Clusters);
    }

    [Fact]
    public void DayOnlyDates_DoNotFormClusters()
    {
        // Installationsdaten aus der Registry haben keine Uhrzeit (00:00) – sonst entstuenden Scheinhaeufungen um Mitternacht.
        var result = Timeline.Build([
            Make("Programm A", Verdict.Check, T0.Date, dayOnly: true),
            Make("Programm B", Verdict.Check, T0.Date, dayOnly: true),
        ]);
        Assert.Empty(result.Clusters);
        Assert.Equal(2, result.Entries.Count);
    }

    [Fact]
    public void ImplausibleTimes_AreIgnored()
    {
        Assert.Null(Make("1601", Verdict.Check, DateTime.FromFileTime(0)).OccurredAt);
        Assert.Null(Make("Zukunft", Verdict.Check, DateTime.Now.AddYears(1)).OccurredAt);
    }
}
