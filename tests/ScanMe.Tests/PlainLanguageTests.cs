using ScanMe.Core.Engine;
using ScanMe.Core.Models;

namespace ScanMe.Tests;

/// <summary>Die Laien-Ampel darf schwache Hinweise nicht als Gefahr darstellen – und echte Belege nicht verharmlosen.</summary>
public class PlainLanguageTests
{
    private static Finding Make(string scanner, string title, FindingCategory cat, params (string Code, int Weight)[] indicators)
    {
        var f = new Finding { ScannerId = scanner, Category = cat, Title = title, FilePath = @"C:\Games\tool.exe" };
        foreach (var (code, weight) in indicators) f.AddIndicator(code, code, weight);
        RiskScorer.Finalize(f);
        PlainLanguage.Apply(f);
        return f;
    }

    [Fact]
    public void UnsignedOnly_IsLikelyHarmless()
    {
        var f = Make("processes", "tool.exe", FindingCategory.Process, ("SIG_NONE", 25), ("LOC_USERAPPDATAROAMING", 15), ("NO_METADATA", 10));
        Assert.Equal(Verdict.LikelyHarmless, f.Verdict);
        Assert.Contains("Signatur", f.PlainSummary);
    }

    [Fact]
    public void Masquerading_IsAct()
    {
        var f = Make("filesystem", "Verdächtige Datei: svch0st.exe", FindingCategory.FileSystem, ("SIG_NONE", 25), ("MASQUERADE", 70));
        Assert.Equal(Verdict.Act, f.Verdict);
    }

    [Fact]
    public void MalwareContent_IsAct_EvenWithLowScore()
    {
        var f = Make("filesystem", "Verdächtige Datei: x.exe", FindingCategory.FileSystem, ("CONTENT_KEYLOGGER", 30));
        Assert.Equal(Verdict.Act, f.Verdict);
    }

    [Fact]
    public void PastPowerShellEvent_AsksTheUser_InsteadOfAlarm()
    {
        var f = Make("eventlog", "PowerShell-Skript: Get-Content", FindingCategory.Malware, ("PS_PS_ENCODED", 45), ("PS_PS_HIDDEN", 25));
        f.Details["Zeitpunkt"] = "23.10.2026 23:10";
        PlainLanguage.Apply(f);
        Assert.Equal(Verdict.Check, f.Verdict);
        Assert.Contains(f.Questions, q => q.Contains("KI-Assistenten"));
        Assert.False(string.IsNullOrEmpty(f.IfUnknown));
    }

    [Fact]
    public void RemoteAccessTool_AsksAboutPhoneScam()
    {
        var f = Make("software", "Software: AnyDesk", FindingCategory.Persistence, ("REMOTE_TOOL", 40));
        Assert.Equal(Verdict.Check, f.Verdict);
        Assert.Contains(f.Questions, q => q.Contains("Telefon"));
    }
}
