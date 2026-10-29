using ScanMe.Core.Engine;
using ScanMe.Core.Models;
using ScanMe.Core.Scanners;
using ScanMe.Core.Yara;

namespace ScanMe.Tests;

/// <summary>
/// YARA-X und das Regelpaket. Die Engine-Tests brauchen Data\yara\ (tools/update-yara.ps1): In GitHub Actions
/// (CI=true) muss sie vorhanden sein, lokal ohne die Dateien werden diese Tests uebersprungen.
/// </summary>
public class YaraTests
{
    private static bool EngineAvailable()
    {
        if (YaraEngine.Unavailable == null) return true;
        Assert.False(Environment.GetEnvironmentVariable("CI") == "true", "YARA fehlt im CI-Build: " + YaraEngine.Unavailable);
        return false;
    }

    [Fact]
    public void Keystream_MatchesIndependentReference()
    {
        // Referenz mit Python: sha256(b"ScanMe rule pack v1" + (0).to_bytes(8, "little")) bzw. Block 1
        var data = new byte[40];
        RulePack.Transform(data);
        Assert.Equal("B88F1C72496BDD0D", Convert.ToHexString(data, 0, 8));
        Assert.Equal("41396843", Convert.ToHexString(data, 32, 4));
    }

    [Fact]
    public void Pack_RoundTrip()
    {
        string payload = "SCANME-YARA-PACK 1\nforge=20990101\nyarax=v9\nrules=1\nTest_Rule\t75\towner/repo\tJane Doe\tBeschreibung\n---\nrule Test_Rule { condition: true }\n";
        byte[] packed = RulePack.Encode(payload);
        Assert.Equal(-1, packed.AsSpan().IndexOf("Test_Rule"u8)); // nicht im Klartext lesbar
        var pack = RulePack.Decode(packed);
        Assert.Equal("20990101", pack.ForgeRelease);
        Assert.Equal("v9", pack.YaraXVersion);
        Assert.Equal(new RulePack.RuleInfo("Test_Rule", 75, "owner/repo", "Jane Doe", "Beschreibung"), pack.Rules["Test_Rule"]);
        Assert.StartsWith("rule Test_Rule", pack.Source);
    }

    [Fact]
    public void Pack_RejectsForeignFiles()
    {
        Assert.Throws<InvalidDataException>(() => RulePack.Decode("PK\u0003\u0004"u8.ToArray()));
    }

    [Fact]
    public void Engine_FindsPattern()
    {
        if (!EngineAvailable()) return;
        using var engine = YaraEngine.FromSource("""
            rule ScanMe_Test_Miner { strings: $a = "stratum+tcp://" condition: $a }
            rule ScanMe_Test_Never { strings: $a = "kommt-nie-vor-4711" condition: $a }
            """);
        Assert.Equal(2, engine.RuleCount);
        Assert.Equal(["ScanMe_Test_Miner"], engine.Scan("pool=stratum+tcp://example:3333"u8));
        Assert.Empty(engine.Scan("harmloser Text"u8));
        Assert.Empty(engine.Scan(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Engine_ScansFiles_WithOptionalSizeLimit()
    {
        if (!EngineAvailable()) return;
        using var engine = YaraEngine.FromSource("""rule ScanMe_Test_Tail { strings: $a = "stratum+tcp://" condition: $a }""");
        string dir = Directory.CreateTempSubdirectory("scanme-yara").FullName;
        try
        {
            // Treffer ganz am Ende einer grossen Datei: Die Datei muss vollstaendig gelesen werden.
            string big = Path.Combine(dir, "gross.bin");
            using (var fs = File.Create(big))
            {
                fs.SetLength(80L * 1024 * 1024);
                fs.Seek(-32, SeekOrigin.End);
                fs.Write("stratum+tcp://x"u8);
            }
            Assert.Equal(["ScanMe_Test_Tail"], engine.ScanFile(big));
            // Nicht gelesen ist etwas anderes als "nichts gefunden".
            Assert.Null(engine.ScanFile(big, YaraEngine.QuickMaxFileSize));
            Assert.Null(engine.ScanFile(Path.Combine(dir, "fehlt.bin")));

            string empty = Path.Combine(dir, "leer.bin");
            File.WriteAllBytes(empty, []);
            Assert.Empty(engine.ScanFile(empty)!);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Engine_ReportsBrokenRules()
    {
        if (!EngineAvailable()) return;
        var ex = Assert.Throws<InvalidOperationException>(() => YaraEngine.FromSource("rule Kaputt { condition: $nicht_definiert }"));
        Assert.Contains("YARA-X", ex.Message);
    }

    [Fact]
    public void RealRulePack_CompilesCompletely()
    {
        // Faengt ab, dass ein Regel-Update (oder der Lizenzfilter) Regeln liefert, die YARA-X nicht uebersetzen kann.
        if (!EngineAvailable()) return;
        using var engine = YaraEngine.Load();
        Assert.True(engine.RuleCount > 4000, $"Nur {engine.RuleCount} Regeln");
        Assert.True(engine.Pack.Rules.Count >= engine.RuleCount - 10);
        Assert.Empty(engine.Scan("Dies ist eine ganz normale Textdatei ohne Auffälligkeiten."u8));
    }

    [Theory]
    [InlineData("SIGNATURE_BASE_HKTL_Mimikatz_Strings", true)]
    [InlineData("DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCOM", true)]
    [InlineData("DITEKSHEN_INDICATOR_TOOL_PWS_Credstealer", true)]
    [InlineData("COD3NYM_DOTNET_Singlefilehost_Bundled_App", true)]   // traf jede .NET-Einzeldatei-EXE, auch ScanMe selbst
    [InlineData("VOLEXITY_Informational_Win_3Cx_Msi", true)]
    [InlineData("MALPEDIA_Win_Redline_Stealer_Auto", false)]
    [InlineData("ESET_Turla_Kazuar", false)]
    public void RuleClassification(string rule, bool soft) => Assert.Equal(soft, MalwareScanner.IsSoftRule(rule));

    [Fact]
    public void MalwareRuleHit_IsAct_ToolRuleHit_IsCheck()
    {
        Finding Make(string code, int weight)
        {
            var f = new Finding { ScannerId = "malware", Category = FindingCategory.FileSystem, Title = "Verdächtige Datei: x.exe" };
            f.AddIndicator(code, code, weight);
            RiskScorer.Finalize(f);
            PlainLanguage.Apply(f);
            return f;
        }
        Assert.Equal(Verdict.Act, Make("YARA_MALWARE", 70).Verdict);
        Assert.Equal(Verdict.Check, Make("YARA_SUSPICIOUS", 30).Verdict);
    }
}
