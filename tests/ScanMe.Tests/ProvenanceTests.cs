using System.Xml.Linq;
using ScanMe.Core.Engine;
using ScanMe.Core.Models;
using ScanMe.Core.Telemetry;
using ScanMe.Core.Trust;

namespace ScanMe.Tests;

/// <summary>"Wer hat PowerShell gestartet?" – eigenes Terminal/KI-Tool vs. Word, Browser oder Win+R.</summary>
public class ProvenanceTests
{
    private static FileTrustInfo Signed(string path) =>
        new() { Path = path, Exists = true, Signature = SignatureState.Valid, Signer = "Publisher", SignerOrganization = "Publisher" };

    private static FileTrustInfo Unsigned(string path) =>
        new() { Path = path, Exists = true, Signature = SignatureState.NotSigned };

    /// <summary>Kette, juengster Prozess zuerst (wie aus dem Protokoll gelesen).</summary>
    private static ProcessChain Chain(params string[] images) =>
        new(images.Select((p, i) => new ProcessNode(p, null, 100 + i, null)).ToList(), "Test");

    [Fact]
    public void TerminalAndAiTool_AreTrusted()
    {
        var chain = Chain(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", @"C:\Program Files\nodejs\node.exe",
                          @"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe");
        var v = Provenance.Classify(chain, Signed);
        Assert.Equal(OriginKind.Trusted, v.Kind);
        Assert.Equal("Code.exe", v.Decisive!.Name);
    }

    [Fact]
    public void UnsignedFakeTerminal_IsNotTrusted()
    {
        var chain = Chain(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", @"C:\Tools\WindowsTerminal.exe");
        Assert.NotEqual(OriginKind.Trusted, Provenance.Classify(chain, Unsigned).Kind);
    }

    [Theory]
    [InlineData(@"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")]
    [InlineData(@"C:\Program Files\Google\Chrome\Application\chrome.exe")]
    [InlineData(@"C:\Windows\System32\mshta.exe")]
    public void OfficeBrowserOrMshta_AreSuspicious(string parent)
    {
        var chain = Chain(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", @"C:\Windows\System32\cmd.exe", parent);
        Assert.Equal(OriginKind.Suspicious, Provenance.Classify(chain, Signed).Kind);
    }

    [Fact]
    public void UnsignedProgramFromDownloads_IsSuspicious()
    {
        var chain = Chain(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", @"C:\Users\x\Downloads\setup_crack.exe");
        Assert.Equal(OriginKind.Suspicious, Provenance.Classify(chain, Unsigned).Kind);
    }

    [Fact]
    public void Explorer_IsRunDialog_NotTrusted()
    {
        // Win+R (ClickFix) und Startmenue sehen gleich aus – darum nie "vertrauenswuerdig".
        var chain = Chain(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", @"C:\Windows\explorer.exe");
        Assert.Equal(OriginKind.RunDialog, Provenance.Classify(chain, Signed).Kind);
    }

    private static Finding PsFinding(params (string Code, int Weight)[] indicators)
    {
        var f = new Finding { ScannerId = "eventlog", Category = FindingCategory.Malware, Title = "PowerShell-Skript: Invoke-WebRequest" };
        f.Details["Zeitpunkt"] = "24.10.2026 10:00";
        f.Details["Gestartet von"] = "Code.exe → powershell.exe (Sysmon)";
        foreach (var (code, weight) in indicators) f.AddIndicator(code, code, weight);
        RiskScorer.Finalize(f);
        PlainLanguage.Apply(f);
        return f;
    }

    [Fact]
    public void TrustedOrigin_RoutineScript_IsLikelyHarmless()
    {
        var f = PsFinding(("PS_PS_DOWNLOAD", 20), ("PS_ORIGIN_TRUSTED", -15));
        Assert.Equal(Verdict.LikelyHarmless, f.Verdict);
    }

    [Fact]
    public void TrustedOrigin_DefenderWeakening_StillNeedsCheck()
    {
        var f = PsFinding(("PS_DEF_WEAKEN", 50), ("PS_ORIGIN_TRUSTED", -15));
        Assert.Equal(Verdict.Check, f.Verdict);
        Assert.Contains(f.Questions, q => q.Contains("kopiert"));
    }

    [Fact]
    public void SuspiciousOrigin_IsAct()
    {
        var f = PsFinding(("PS_PS_ENCODED", 45), ("PS_ORIGIN_SUSPICIOUS", 50));
        Assert.Equal(Verdict.Act, f.Verdict);
    }

    [Fact]
    public void SysmonConfig_IsWellFormedXml()
    {
        var doc = XDocument.Parse(SysmonConfig.Build());
        Assert.Equal("Sysmon", doc.Root!.Name.LocalName);
        Assert.NotEmpty(doc.Descendants("ProcessCreate"));
        // Datenschutz: Zwischenablage wird nicht aufgezeichnet
        Assert.Contains(doc.Descendants("ClipboardChange"), e => (string?)e.Attribute("onmatch") == "include" && !e.HasElements);
    }
}
