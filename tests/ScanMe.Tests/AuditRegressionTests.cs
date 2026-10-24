using ScanMe.Core.Engine;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Models;

namespace ScanMe.Tests;

/// <summary>
/// Abnahmekriterien aus dem Audit "Fehlalarm Verdaechtiges PowerShell-Skript" (24.10.2026).
/// </summary>
public class AuditRegressionTests
{
    // Ausschnitt aus dem automatisch erzeugten CDXML-Code des Defender-Moduls (Teil 13/22 im Audit)
    private const string DefenderModuleCode = """
        [CmdletBinding(DefaultParameterSetName='Remove2', SupportsShouldProcess=$true)]
        param(
            [Parameter(ParameterSetName='Remove2')]
            [switch]
            ${DisableAutoExclusions},
            [switch]
            ${MAPSReporting},
            [bool]
            ${DisableRealtimeMonitoring}
        )
        $__cmdletization_objectModelWrapper = $PSCmdlet.GetVariableValue('__cmdletization_objectModelWrapper')
        """;

    // --- E1: Aufrufe statt Text ---

    [Fact]
    public void E1_DefenderModuleCode_IsNotAnAlarm()
    {
        Assert.True(ScriptBlockAnalyzer.IsGeneratedModuleCode(DefenderModuleCode));
        Assert.Empty(ScriptBlockAnalyzer.FindDefenderCalls(DefenderModuleCode));
    }

    [Theory]
    [InlineData("Import-Module Defender")]
    [InlineData("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled")]
    [InlineData("$p = Get-MpPreference; $p.DisableRealtimeMonitoring")]
    public void E1_ReadingDefenderStatus_IsNotAnAlarm(string script) =>
        Assert.DoesNotContain(ScriptBlockAnalyzer.FindDefenderCalls(script), c => c.WeakensProtection);

    [Theory]
    [InlineData(@"Add-MpPreference -ExclusionPath C:\x")]
    [InlineData(@"Add-MpPreference -ExclusionPath 'C:\Users\Public\a b'")]
    [InlineData("Set-MpPreference -DisableRealtimeMonitoring $true")]
    [InlineData("set-mppreference -ExclusionProcess evil.exe -Force")]
    public void E1_RealWeakeningCall_IsDetected(string script) =>
        Assert.Contains(ScriptBlockAnalyzer.FindDefenderCalls(script), c => c.WeakensProtection);

    // --- E2: Richtung beachten ---

    [Theory]
    [InlineData(@"Remove-MpPreference -ExclusionPath 'C:\Users\Test\AppData\Local\Temp'")]
    [InlineData("Set-MpPreference -DisableRealtimeMonitoring $false")]
    public void E2_ImprovingProtection_IsNotWeakening(string script)
    {
        var calls = ScriptBlockAnalyzer.FindDefenderCalls(script);
        Assert.NotEmpty(calls);
        Assert.All(calls, c => Assert.False(c.WeakensProtection));
    }

    [Fact]
    public void E2_KeywordRuleNoLongerFiresOnModuleDeclarations()
    {
        // Die alte Schluesselwort-Regel darf fuer Skriptbloecke nicht mehr ausschlaggebend sein:
        // Der Scanner filtert PS_DEFENDER_OFF und nutzt stattdessen die Aufrufanalyse.
        Assert.Empty(ScriptBlockAnalyzer.FindDefenderCalls(DefenderModuleCode));
    }

    // --- E3/E4: Ausnahmen-Audit ---

    private const string RoamingBroker = @"C:\Users\Test\AppData\Roaming\Microsoft\Windows\Applications\Runtime Broker.exe";

    [Fact]
    public void E3_MasqueradingExeExclusion_IsFlagged()
    {
        var ind = ExclusionRisk.Assess("Pfad", RoamingBroker, []);
        Assert.Contains(ind, i => i.Code == "EXCL_MASQUERADE");
    }

    [Fact]
    public void E4_ExclusionPointingToQuarantinedMalware_IsHighOrCritical()
    {
        var ind = ExclusionRisk.Assess("Pfad", RoamingBroker, [RoamingBroker]);
        Assert.Contains(ind, i => i.Code == "EXCL_QUARANTINED");
        var f = new Finding { ScannerId = "t", Category = FindingCategory.SecurityConfig, Title = "t" };
        f.Indicators.AddRange(ind);
        RiskScorer.Finalize(f);
        Assert.True(f.Severity >= Severity.High, $"Severity {f.Severity}, Score {f.Score}");
    }

    [Theory]
    [InlineData(@"C:\Users\Test\AppData\Roaming\SomeVendor\ExLoader\games")]
    [InlineData(@"C:\Users\Test\Desktop\GHax")]
    [InlineData(@"D:\Games\Some Cheat Loader")]
    public void E3_CheatLoaderExclusions_AreFlagged(string path) =>
        Assert.Contains(ExclusionRisk.Assess("Pfad", path, []), i => i.Code == "EXCL_CHEAT");

    [Fact]
    public void E3_TempFolderExclusion_IsBroad() =>
        Assert.Contains(ExclusionRisk.Assess("Pfad", @"C:\Users\Test\AppData\Local\Temp", []), i => i.Code == "EXCL_BROAD");

    [Fact]
    public void E3_ExecutableExtensionExclusion_IsHigh() =>
        Assert.Contains(ExclusionRisk.Assess("Dateiendung", ".exe", []), i => i.Weight >= 60);
}
