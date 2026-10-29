using ScanMe.Core.Engine;
using ScanMe.Core.Models;
using ScanMe.Core.Reporting;

namespace ScanMe.Tests;

/// <summary>
/// "Wie sicher ist das?": Der Nutzer muss erkennen, ob ein Virenschutz den Verdacht bestaetigt hat, ob nur ScanMes
/// eigene Merkmale anschlagen – und dass ein echtes Fernwartungsprogramm kein Virus ist.
/// </summary>
public class CertaintyTests
{
    private static Finding Make(Action<Finding> checks, params (string Code, int Weight)[] indicators)
    {
        var f = new Finding { ScannerId = "filesystem", Category = FindingCategory.FileSystem, Title = "Verdächtige Datei: x.dll", FilePath = @"C:\Users\a\AppData\Local\Temp\x.dll" };
        foreach (var (code, weight) in indicators) f.AddIndicator(code, code, weight);
        checks(f);
        RiskScorer.Finalize(f);
        PlainLanguage.Apply(f);
        return f;
    }

    [Fact]
    public void DefenderDetection_IsConfirmed()
    {
        var f = Make(f => f.Checked(Check.Detection(Check.Defender, "Trojan:Win32/Lumma.A!MTB", pua: false)), ("DEFENDER_DETECTED", 90));
        Assert.Equal(Verdict.Act, f.Verdict);
        Assert.StartsWith("Bestätigt", f.Certainty);
    }

    [Fact]
    public void PuaDetection_IsNotCalledMalware()
    {
        var f = Make(f => f.Checked(Check.Detection(Check.Defender, "PUA:Win32/Presenoker", pua: true)), ("DEFENDER_DETECTED", 45));
        Assert.Contains("unerwünschtes Programm", f.Certainty);
        Assert.DoesNotContain("Bestätigt", f.Certainty);
    }

    [Fact]
    public void HeuristicOnly_WithCleanDefender_IsMarkedUnconfirmed()
    {
        // Typischer Fall "gefaehrliche DLL im Temp-Ordner": harte Merkmale, aber Defender findet nichts.
        var f = Make(f => f.Checked(Check.Defender, CheckResult.Good, "hat die Datei geprüft: keine Bedrohung erkannt"),
            ("SIG_NONE", 25), ("RTLO", 60));
        Assert.Equal(Verdict.Act, f.Verdict);
        Assert.StartsWith("Nicht bestätigt: Microsoft Defender hat die Datei geprüft", f.Certainty);
        Assert.Contains("Fehlalarm", f.PlainSummary);
    }

    [Fact]
    public void HeuristicOnly_WithoutAntivirus_SaysNobodyChecked()
    {
        var f = Make(_ => { }, ("SIG_NONE", 25), ("RTLO", 60));
        Assert.StartsWith("Nicht bestätigt: Kein Virenschutz", f.Certainty);
        Assert.DoesNotContain("Fehlalarm", f.PlainSummary);
    }

    [Fact]
    public void YaraMalwareRule_WithCleanDefender_IsPartlyConfirmed()
    {
        var f = Make(f =>
        {
            f.Checked(Check.Yara, CheckResult.Bad, "Regel für Schadsoftware passt: X");
            f.Checked(Check.Defender, CheckResult.Good, "keine Bedrohung");
        }, ("YARA_MALWARE", 70));
        Assert.StartsWith("Teilweise bestätigt", f.Certainty);
        // Bei einem YARA-Treffer nicht von "Fehlalarm" im Hauptsatz sprechen – das entscheidet VirusTotal.
        Assert.DoesNotContain("Fehlalarm", f.PlainSummary);
    }

    [Fact]
    public void YaraMalwareRule_OnSignedFile_IsOnlyCheck()
    {
        // CAPE_Bumblebee traf die signierte claude.exe – das darf kein "Handeln" sein.
        var f = Make(f => f.Checked(Check.Yara, CheckResult.Warning, "Regel passt, aber signiert"),
            ("YARA_MALWARE_SIGNED", 40), ("SIG_VALID", -25));
        Assert.Equal(Verdict.Check, f.Verdict);
        Assert.StartsWith("Unklar", f.Certainty);
    }

    [Fact]
    public void SignedRemoteAccessTool_IsNoVirus()
    {
        // Frueher wirkte RustDesk wie Schadsoftware – es ist ein echtes Programm, gefaehrlich nur bei Missbrauch.
        var f = Make(f => f.Checked(Check.Signature, CheckResult.Good, "gültig"), ("TOOL_REMOTEACCESS", 30), ("SIG_VALID", -25), ("LOC_DOWNLOADS", 5));
        Assert.StartsWith("Kein Virus", f.Certainty);
        Assert.Contains("Original", f.Certainty);
    }

    [Fact]
    public void RemoteAccessTool_WithHardEvidence_IsNotWhitewashed()
    {
        var f = Make(_ => { }, ("TOOL_REMOTEACCESS", 30), ("MASQUERADE", 70));
        Assert.DoesNotContain("Kein Virus", f.Certainty);
    }

    [Fact]
    public void LaterCleanResult_DoesNotOverwriteDetection()
    {
        var f = new Finding { ScannerId = "t", Category = FindingCategory.Malware, Title = "t" };
        f.Checked(Check.Detection(Check.Defender, "Trojan:Win32/X", pua: false));
        f.Checked(Check.Defender, CheckResult.Good, "keine Bedrohung");
        Assert.Equal(CheckResult.Bad, Assert.Single(f.Checks).Result);

        f.Checked(Check.Signature, CheckResult.Neutral, "keine");
        f.Checked(Check.Signature, CheckResult.Good, "gültig");
        Assert.Equal(CheckResult.Good, f.Checks.Single(c => c.Source == Check.Signature).Result);
    }

    [Fact]
    public void CopyText_ContainsEverythingTheUserSees()
    {
        var f = Make(f => f.Checked(Check.Defender, CheckResult.Good, "hat die Datei geprüft: keine Bedrohung erkannt"),
            ("SIG_NONE", 25), ("RTLO", 60));
        f.Description = "Datei mit Umkehrzeichen im Namen.";
        f.Detail("SHA256", "ABC123");
        string text = FindingText.ToText(f);

        Assert.StartsWith("Verdächtige Datei: x.dll", text);
        Assert.Contains(@"Ort: C:\Users\a\AppData\Local\Temp\x.dll", text);
        Assert.Contains(f.PlainSummary, text);
        Assert.Contains("WIE SICHER IST DAS?", text);
        Assert.Contains("✔ Microsoft Defender: hat die Datei geprüft", text);
        Assert.Contains("Datei mit Umkehrzeichen im Namen.", text);
        Assert.Contains("+ 60  RTLO", text);
        Assert.Contains("SHA256: ABC123", text);
        // Leere Abschnitte bekommen keine Ueberschrift.
        Assert.DoesNotContain("HINTERGRUND", text);
    }
}
