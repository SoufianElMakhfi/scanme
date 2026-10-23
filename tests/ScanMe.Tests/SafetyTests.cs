using System.Diagnostics;
using ScanMe.Core.Actions;
using ScanMe.Core.Util;

namespace ScanMe.Tests;

/// <summary>Die wichtigste Zusage der App: Windows-Komponenten werden nie angetastet.</summary>
public class SafetyTests
{
    [Theory]
    [InlineData(@"%SystemRoot%\System32\kernel32.dll")]
    [InlineData(@"%SystemRoot%\System32\svchost.exe")]
    [InlineData(@"%SystemRoot%\System32\lsass.exe")]
    [InlineData(@"%SystemRoot%\explorer.exe")]
    [InlineData(@"%SystemRoot%\System32\drivers\etc\hosts")]
    [InlineData(@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe")]
    public void SystemFiles_AreNeverQuarantined(string path)
    {
        string full = Environment.ExpandEnvironmentVariables(path);
        Assert.NotNull(SafetyGuard.CheckFile(full));
    }

    [Fact]
    public void QuarantineRefusesSystemFile_AndLeavesItInPlace()
    {
        string notepad = Path.Combine(PathUtil.System32, "notepad.exe");
        if (!File.Exists(notepad)) return;
        var result = Quarantine.Add(notepad, "test");
        Assert.False(result.Success);
        Assert.True(File.Exists(notepad));
    }

    [Theory]
    [InlineData("lsass")]
    [InlineData("csrss")]
    [InlineData("wininit")]
    [InlineData("services")]
    [InlineData("smss")]
    public void CriticalProcesses_AreNeverKilled(string name)
    {
        foreach (var p in Process.GetProcessesByName(name))
            using (p)
                Assert.NotNull(SafetyGuard.CheckProcess(p.Id));
    }

    [Fact]
    public void KernelAndSelf_AreNeverKilled()
    {
        Assert.NotNull(SafetyGuard.CheckProcess(0));
        Assert.NotNull(SafetyGuard.CheckProcess(4));
        Assert.NotNull(SafetyGuard.CheckProcess(Environment.ProcessId));
    }

    [Theory]
    [InlineData("RpcSs")]
    [InlineData("WinDefend")]
    [InlineData("EventLog")]
    [InlineData("Winmgmt")]
    public void CoreServices_AreNeverDisabled(string service) =>
        Assert.NotNull(SafetyGuard.CheckService(service));

    [Fact]
    public void Quarantine_RoundTrip_RestoresIdenticalFile()
    {
        string dir = Path.Combine(Path.GetTempPath(), "scanme-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string file = Path.Combine(dir, "probe.exe");
        byte[] content = new byte[100_000];
        Random.Shared.NextBytes(content);
        File.WriteAllBytes(file, content);
        try
        {
            var add = Quarantine.Add(file, "test");
            Assert.True(add.Success, add.Message);
            Assert.False(File.Exists(file));

            var item = Quarantine.List().First(i => i.OriginalPath == file);
            var restore = Quarantine.Restore(item.Id);
            Assert.True(restore.Success, restore.Message);
            Assert.Equal(content, File.ReadAllBytes(file));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
