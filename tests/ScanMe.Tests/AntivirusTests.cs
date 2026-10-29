using System.Text;
using ScanMe.Core.Antivirus;
using ScanMe.Core.Scanners;

namespace ScanMe.Tests;

/// <summary>
/// Anbindung des installierten Virenschutzes (MpCmdRun und AMSI). Der echte AMSI-Test loest im Virenschutz
/// eine Meldung aus und laeuft daher nur mit SCANME_AMSI_TEST=1.
/// </summary>
public class AntivirusTests
{
    /// <summary>EICAR-Testzeichenkette, rueckwaerts abgelegt, damit der Virenschutz nicht die Testdatei selbst meldet.</summary>
    private static byte[] Eicar() =>
        Encoding.ASCII.GetBytes(new string(@"*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\4[PA@%P!O5X".Reverse().ToArray()));

    [Fact]
    public void ParsesDefenderThreatList()
    {
        const string output = """
            Scan starting...
            Scan finished.
            Scanning C:\Users\Max\Downloads found 2 threats.

            <===========================LIST OF DETECTED THREATS==========================>
            ----------------------------- Threat information ------------------------------
            Threat                  : Trojan:Win32/Lumma.A!MTB
            Resources               : 2 total
                file                : C:\Users\Max\Downloads\setup.exe
                file                : C:\Users\Max\Downloads\crack.zip->setup.exe
            -------------------------------------------------------------------------------
            ----------------------------- Threat information ------------------------------
            Threat                  : PUA:Win32/Presenoker
            Resources               : 1 total
                containerfile       : C:\Users\Max\Downloads\Tools Ä.zip
            -------------------------------------------------------------------------------
            ----------------------------- Threat information ------------------------------
            Threat                  : Trojan:Win32/Glupteba
            Resources               : 2 total
                regkey              : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\csrss
                service             : WinmonProcessMonitor
            -------------------------------------------------------------------------------
            """;
        var d = DefenderCli.ParseDetections(output.Replace("\n", "\r\n"));
        Assert.Equal(5, d.Count);
        Assert.Equal(new DefenderCli.Detection("Trojan:Win32/Lumma.A!MTB", @"C:\Users\Max\Downloads\setup.exe", null), d[0]);
        Assert.Equal(new DefenderCli.Detection("Trojan:Win32/Lumma.A!MTB", @"C:\Users\Max\Downloads\crack.zip", "setup.exe"), d[1]);
        Assert.Equal(@"C:\Users\Max\Downloads\Tools Ä.zip", d[2].Path);
        Assert.True(d[2].IsFile);
        Assert.True(DefenderCli.IsPuaName(d[2].Threat));
        Assert.False(DefenderCli.IsPuaName(d[0].Threat));
        Assert.Equal(new DefenderCli.Detection("Trojan:Win32/Glupteba", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\csrss", null, "regkey"), d[3]);
        Assert.Equal(("service", "WinmonProcessMonitor"), (d[4].Kind, d[4].Path));
        Assert.False(d[4].IsFile);
    }

    [Fact]
    public void CleanScanHasNoDetections()
    {
        Assert.Empty(DefenderCli.ParseDetections("Scan starting...\r\nScan finished.\r\nScanning C:\\x found no threats.\r\n"));
    }

    [Fact]
    public void OwnAmsiChecksAreNotDefenderFindings()
    {
        // So traegt Defender eine AMSI-Pruefung ein (beobachtet mit Defender 4.18.26100)
        string self = Environment.ProcessPath!;
        string[] amsi = [@"amsi:_\Device\HarddiskVolume3\" + self[3..]];
        Assert.True(MalwareScanner.IsOwnAmsiCheck(amsi, self));
        Assert.False(MalwareScanner.IsOwnAmsiCheck(amsi, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"));
        Assert.False(MalwareScanner.IsOwnAmsiCheck([@"file:_" + self], self));
        Assert.False(MalwareScanner.IsAmsiDetection([]));
    }

    [Theory]
    [InlineData(0, AmsiVerdict.Clean)]
    [InlineData(1, AmsiVerdict.Clean)]
    [InlineData(0x4000, AmsiVerdict.BlockedByAdmin)]
    [InlineData(32768, AmsiVerdict.Malware)]
    [InlineData(40000, AmsiVerdict.Malware)]
    public void InterpretsAmsiResult(int result, AmsiVerdict expected) => Assert.Equal(expected, AmsiScanner.Interpret(result));

    [Fact]
    public void Amsi_DetectsEicar()
    {
        if (Environment.GetEnvironmentVariable("SCANME_AMSI_TEST") != "1") return;
        using var amsi = AmsiScanner.TryOpen(out var reason);
        Assert.True(amsi != null, reason);
        Assert.NotEmpty(amsi!.Providers);
        Assert.Equal(AmsiVerdict.Clean, amsi.Scan("Hallo, ganz harmlos."u8.ToArray(), "scanme-test-clean"));
        Assert.Equal(AmsiVerdict.Malware, amsi.Scan(Eicar(), "scanme-test-eicar"));
    }
}
