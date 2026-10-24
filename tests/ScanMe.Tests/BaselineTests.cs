using System.Reflection;
using ScanMe.Core.Baseline;

namespace ScanMe.Tests;

public class BaselineTests
{
    private static BaselineSnapshot Snap(params (string Cat, string Key, string Value)[] items)
    {
        var s = new BaselineSnapshot { CreatedAt = new DateTime(2026, 1, 1) };
        foreach (var (cat, key, value) in items)
        {
            if (!s.Categories.TryGetValue(cat, out var d)) s.Categories[cat] = d = new(StringComparer.OrdinalIgnoreCase);
            d[key] = value;
        }
        return s;
    }

    [Fact]
    public void Compare_FindsAddedRemovedAndChanged()
    {
        var before = Snap(("Dienst", "A", "a.exe"), ("Dienst", "B", "b.exe"));
        var after = Snap(("Dienst", "A", "a2.exe"), ("Dienst", "C", "c.exe"));
        var changes = BaselineService.Compare(before, after);
        Assert.Contains(changes, c => c.Key == "A" && c.Kind == ChangeKind.Changed);
        Assert.Contains(changes, c => c.Key == "B" && c.Kind == ChangeKind.Removed);
        Assert.Contains(changes, c => c.Key == "C" && c.Kind == ChangeKind.Added);
        Assert.Equal(3, changes.Count);
    }

    [Fact]
    public void Compare_IdenticalState_HasNoChanges() =>
        Assert.Empty(BaselineService.Compare(Snap(("Autostart", "x", "1")), Snap(("Autostart", "X", "1"))));

    [Fact]
    public void Tampering_IsDetected()
    {
        var s = Snap(("Autostart", "x", "1"));
        s.Checksum = typeof(BaselineService).GetMethod("ComputeChecksum", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [s]) as string;
        Assert.True(BaselineService.IsIntact(s));
        s.Categories["Autostart"]["malware"] = "evil.exe"; // Malware traegt sich nachtraeglich als "bekannt" ein
        Assert.False(BaselineService.IsIntact(s));
    }
}
