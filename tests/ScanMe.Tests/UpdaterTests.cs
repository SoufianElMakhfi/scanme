using System.IO.Compression;
using System.Security.Cryptography;
using ScanMe.Core.Trust;
using ScanMe.Core.Updates;

namespace ScanMe.Tests;

/// <summary>Selbst-Update: Nur gepruefte Pakete, Austausch mit Rollback, Aufraeumen nur eigener Dateien.</summary>
public sealed class UpdaterTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "ScanMeUpdaterTests_" + Guid.NewGuid().ToString("N"));
    private string Install => Path.Combine(_root, "install");
    private string Staging => Path.Combine(_root, "staging");
    private string Work => Path.Combine(_root, "work");

    public UpdaterTests()
    {
        Directory.CreateDirectory(Install);
        Directory.CreateDirectory(Staging);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private static void Write(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    private string Zip(string name = "ScanMe-win-x64.zip")
    {
        string zip = Path.Combine(_root, name);
        ZipFile.CreateFromDirectory(Staging, zip);
        return zip;
    }

    private static string Sums(string zip, string? hash = null) =>
        $"{hash ?? Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(zip)))}  {Path.GetFileName(zip)}\nAAAA  ScanMe-win-arm64.zip\n";

    [Fact]
    public void Checksum_Accepted_WhenMatching()
    {
        Write(Path.Combine(Staging, "ScanMe.exe"), "neu");
        string zip = Zip();
        AppUpdater.VerifyChecksum(zip, Sums(zip));
        AppUpdater.VerifyChecksum(zip, Sums(zip).ToLowerInvariant().Replace("scanme-win-x64.zip", "ScanMe-win-x64.zip"));
    }

    [Fact]
    public void Checksum_Rejected_WhenChangedOrMissing()
    {
        Write(Path.Combine(Staging, "ScanMe.exe"), "neu");
        string zip = Zip();
        Assert.Throws<InvalidDataException>(() => AppUpdater.VerifyChecksum(zip, Sums(zip, new string('0', 64))));
        Assert.Throws<InvalidDataException>(() => AppUpdater.VerifyChecksum(zip, "AAAA  andere-datei.zip"));
    }

    [Fact]
    public void Apply_ReplacesFiles_KeepsBackups_AndAddsNewOnes()
    {
        Write(Path.Combine(Install, "ScanMe.exe"), "alt");
        Write(Path.Combine(Install, "Data", "loldrivers.json"), "alt");
        Write(Path.Combine(Install, "eigene-notiz.txt"), "vom Nutzer");
        Write(Path.Combine(Staging, "ScanMe.exe"), "neu");
        Write(Path.Combine(Staging, "Data", "loldrivers.json"), "neu");
        Write(Path.Combine(Staging, "Data", "yara", "rules.bin"), "neu");

        AppUpdater.Apply(Staging, Install, Work);

        Assert.Equal("neu", File.ReadAllText(Path.Combine(Install, "ScanMe.exe")));
        Assert.Equal("neu", File.ReadAllText(Path.Combine(Install, "Data", "yara", "rules.bin")));
        Assert.Equal("alt", File.ReadAllText(Path.Combine(Install, "ScanMe.exe.old")));
        Assert.Equal("vom Nutzer", File.ReadAllText(Path.Combine(Install, "eigene-notiz.txt")));
    }

    [Fact]
    public void Cleanup_DeletesOnlyOwnBackups()
    {
        // Liegt ScanMe z. B. im Download-Ordner, duerfen fremde *.old-Dateien dort nicht verschwinden.
        Write(Path.Combine(Install, "ScanMe.exe"), "alt");
        Write(Path.Combine(Install, "fremde-sicherung.old"), "vom Nutzer");
        Write(Path.Combine(Staging, "ScanMe.exe"), "neu");
        AppUpdater.Apply(Staging, Install, Work);

        AppUpdater.CleanupAfterUpdate(Work, Install);

        Assert.False(File.Exists(Path.Combine(Install, "ScanMe.exe.old")));
        Assert.True(File.Exists(Path.Combine(Install, "fremde-sicherung.old")));
        Assert.False(File.Exists(Path.Combine(Work, "cleanup.txt")));
    }

    [Fact]
    public void Cleanup_IgnoresInjectedPaths()
    {
        // Die Aufraeumliste wird mit Adminrechten abgearbeitet: Untergeschobene Eintraege duerfen nichts loeschen.
        string outside = Path.Combine(_root, "wichtig.dll");
        string notBackup = Path.Combine(Install, "ScanMe.exe");
        string traversal = Path.Combine(Install, "..", "wichtig.old");
        Write(outside, "x");
        Write(notBackup, "x");
        Write(Path.Combine(_root, "wichtig.old"), "x");
        Write(Path.Combine(Work, "cleanup.txt"), string.Join("\n", outside, notBackup, traversal, "relativ.old"));

        AppUpdater.CleanupAfterUpdate(Work, Install);

        Assert.True(File.Exists(outside));
        Assert.True(File.Exists(notBackup));
        Assert.True(File.Exists(Path.Combine(_root, "wichtig.old")));
    }

    [Theory]
    [InlineData(@"ScanMe.exe.old", true)]
    [InlineData(@"Data\loldrivers.json.old3", true)]
    [InlineData(@"ScanMe.exe", false)]
    [InlineData(@"ScanMe.exe.older", false)]
    [InlineData(@"..\ScanMe.exe.old", false)]
    public void OwnBackup_OnlyOldFilesInsideInstallDir(string relative, bool expected) =>
        Assert.Equal(expected, AppUpdater.IsOwnBackup(Path.Combine(Install, relative), Install));

    [Fact]
    public void Apply_RenamesFileThatIsInUse()
    {
        // Wie eine laufende EXE: Windows erlaubt Umbenennen (FILE_SHARE_DELETE), aber kein Ueberschreiben.
        Write(Path.Combine(Install, "ScanMe.exe"), "alt");
        Write(Path.Combine(Staging, "ScanMe.exe"), "neu");
        using (new FileStream(Path.Combine(Install, "ScanMe.exe"), FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
            AppUpdater.Apply(Staging, Install, Work);
        Assert.Equal("neu", File.ReadAllText(Path.Combine(Install, "ScanMe.exe")));
    }

    [Fact]
    public void Apply_RollsBackEverything_OnFailure()
    {
        Write(Path.Combine(Install, "ScanMe.exe"), "alt");
        Write(Path.Combine(Install, "Data"), "eine Datei, wo das Update einen Ordner braucht");
        Write(Path.Combine(Staging, "ScanMe.exe"), "neu");
        Write(Path.Combine(Staging, "Data", "loldrivers.json"), "neu");

        Assert.ThrowsAny<IOException>(() => AppUpdater.Apply(Staging, Install, Work));

        Assert.Equal("alt", File.ReadAllText(Path.Combine(Install, "ScanMe.exe")));
        Assert.False(File.Exists(Path.Combine(Install, "ScanMe.exe.old")));
    }

    [Fact]
    public void Package_MustBeNewerVersion()
    {
        // ScanMe.Core.dll traegt dieselbe Version wie die App – als "ScanMe.exe" in beiden Ordnern: nicht neuer.
        string core = typeof(AppUpdater).Assembly.Location;
        File.Copy(core, Path.Combine(Install, "ScanMe.exe"));
        File.Copy(core, Path.Combine(Staging, "ScanMe.exe"));
        var ex = Assert.Throws<InvalidDataException>(() => AppUpdater.VerifyPackage(Staging, Install));
        Assert.Contains("nicht neuer", ex.Message);
    }

    [Fact]
    public void Package_WithoutApp_IsRejected()
    {
        Write(Path.Combine(Staging, "irgendwas.exe"), "x");
        Assert.Throws<InvalidDataException>(() => AppUpdater.VerifyPackage(Staging, Install));
    }

    private static FileTrustInfo Trust(SignatureState state, string? signer) =>
        new() { Path = @"C:\x\ScanMe.exe", Exists = true, Signature = state, Signer = signer };

    [Fact]
    public void Publisher_SignedVersion_AcceptsOnlySamePublisher()
    {
        var current = Trust(SignatureState.Valid, "SignPath Foundation");
        AppUpdater.CheckPublisher(current, Trust(SignatureState.Valid, "SignPath Foundation"));
        // Uebernommenes GitHub-Konto: Pruefsummen passen, aber Signatur fehlt oder stammt von jemand anderem.
        Assert.Throws<InvalidDataException>(() => AppUpdater.CheckPublisher(current, Trust(SignatureState.NotSigned, null)));
        Assert.Throws<InvalidDataException>(() => AppUpdater.CheckPublisher(current, Trust(SignatureState.Valid, "Evil Corp")));
        Assert.Throws<InvalidDataException>(() => AppUpdater.CheckPublisher(current, Trust(SignatureState.Invalid, "SignPath Foundation")));
    }

    [Fact]
    public void Publisher_UnsignedVersion_ReliesOnChecksumOnly()
    {
        AppUpdater.CheckPublisher(Trust(SignatureState.NotSigned, null), Trust(SignatureState.NotSigned, null));
        AppUpdater.CheckPublisher(Trust(SignatureState.NotSigned, null), Trust(SignatureState.Valid, "SignPath Foundation"));
    }
}
