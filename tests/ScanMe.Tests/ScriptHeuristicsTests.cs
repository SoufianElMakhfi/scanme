using ScanMe.Core.Scanners;

namespace ScanMe.Tests;

/// <summary>Gebuendelter Browser-Code in Temp ist kein Phishing-Anhang – einzelne WSH-Skripte schon.</summary>
public class ScriptHeuristicsTests
{
    [Theory]
    [InlineData("var sh = WScript.CreateObject(\"WScript.Shell\"); sh.Run(\"cmd /c calc\");", true)]
    [InlineData("var fso = new ActiveXObject(\"Scripting.FileSystemObject\");", true)]
    [InlineData("var s = new ActiveXObject(\"WScr\" + \"ipt.Shell\");", true)]
    [InlineData("var x = new ActiveXObject(t);", true)]
    [InlineData("var w = GetObject(\"winmgmts:\\\\\\\\.\\\\root\\\\cimv2\");", true)]
    [InlineData("var st = new ActiveXObject('ADODB.Stream');", true)]
    // Browser-Code
    [InlineData("const newScriptTag = document.createElement('script');", false)]
    [InlineData("var r = new XMLHttpRequest(); r.open('GET', url);", false)]
    [InlineData("try { x = new ActiveXObject(\"Microsoft.XMLHTTP\"); } catch (e) { x = new ActiveXObject('Msxml2.XMLHTTP.6.0'); }", false)]
    [InlineData("if (typeof ActiveXObject !== 'undefined') {}", false)]
    [InlineData("store.getObject('settings');", false)]
    public void RecognizesWindowsScriptHostUse(string script, bool expected) =>
        Assert.Equal(expected, FileSystemScanner.UsesScriptHost(script));

    [Fact]
    public void BundledWebCodeIsRecognized()
    {
        string root = Path.Combine(Path.GetTempPath(), "scanme-bundle-" + Guid.NewGuid().ToString("N"));
        try
        {
            // Entpackte Browser-Erweiterung: Manifest zwei Ebenen hoeher
            string ext = Directory.CreateDirectory(Path.Combine(root, "CRX_INSTALL", "content_scripts")).FullName;
            File.WriteAllText(Path.Combine(root, "CRX_INSTALL", "manifest.json"), "{}");
            File.WriteAllText(Path.Combine(ext, "a.js"), "");
            Assert.True(FileSystemScanner.IsBundledWebDir(new DirectoryInfo(ext)));

            // Viele Skripte nebeneinander
            string assets = Directory.CreateDirectory(Path.Combine(root, "assets")).FullName;
            for (int i = 0; i < 5; i++) File.WriteAllText(Path.Combine(assets, $"m{i}.js"), "");
            Assert.True(FileSystemScanner.IsBundledWebDir(new DirectoryInfo(assets)));

            // Ausgepackter Mailanhang mit einem einzelnen Skript
            string zip = Directory.CreateDirectory(Path.Combine(root, "Temp1_Rechnung.zip")).FullName;
            File.WriteAllText(Path.Combine(zip, "Rechnung.js"), "");
            Assert.False(FileSystemScanner.IsBundledWebDir(new DirectoryInfo(zip)));
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }
}
