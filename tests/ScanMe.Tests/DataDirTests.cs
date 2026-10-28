using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using ScanMe.Core.Actions;
using ScanMe.Core.Util;

namespace ScanMe.Tests;

/// <summary>
/// Der Datenordner wird mit Adminrechten gelesen. Normale Benutzer duerfen dort nichts unterschieben koennen
/// (Aufraeumliste, Rueckgaengig-Journal, Quarantaene-Eintraege, Ignorierliste).
/// </summary>
public sealed class DataDirTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "ScanMeDataDirTests_" + Guid.NewGuid().ToString("N"));
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public DataDirTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    [Theory]
    [InlineData("0123456789abcdef0123456789ABCDEF", true)]
    [InlineData(@"..\..\Windows\System32", false)]
    [InlineData("0123456789abcdef0123456789abcde", false)]
    [InlineData("0123456789abcdef0123456789abcdeg", false)]
    public void QuarantineIds_CannotLeaveTheQuarantineFolder(string id, bool valid) =>
        Assert.Equal(valid, Quarantine.IsValidId(id));

    [Fact]
    public void Secure_SetsAsideForeignEntries_AndLocksOutUsers()
    {
        if (!SystemEnv.IsElevated) return; // Besitzer "Administratoren" setzen geht nur mit Adminrechten (CI laeuft so)

        string data = Path.Combine(_root, "data");
        string victim = Path.Combine(_root, "victim");
        Directory.CreateDirectory(Path.Combine(data, "Reports"));
        File.WriteAllText(Path.Combine(data, "settings.json"), "{}");
        Directory.CreateDirectory(victim);
        File.WriteAllText(Path.Combine(victim, "keep.txt"), "x");

        // Wie von einem normalen Benutzer untergeschoben: fremder Besitzer bzw. Link auf einen anderen Ordner.
        string planted = Path.Combine(data, "Reports", "cleanup.txt");
        File.WriteAllText(planted, "C:\\Windows\\System32\\x.dll");
        SetOwner(new FileInfo(planted), WindowsIdentity.GetCurrent().User!);
        Run("cmd.exe", $"/c mklink /J \"{Path.Combine(data, "Update")}\" \"{victim}\"");

        var setAside = new List<string>();
        AppPaths.Secure(data, setAside);

        Assert.True(File.Exists(Path.Combine(data, "settings.json")));
        Assert.False(File.Exists(planted));
        Assert.False(Directory.Exists(Path.Combine(data, "Update")));
        Assert.Equal(2, setAside.Count);
        Assert.True(File.Exists(Path.Combine(victim, "keep.txt"))); // Link nur verschoben, Ziel unberuehrt

        var security = new DirectoryInfo(data).GetAccessControl();
        Assert.Equal(Admins, security.GetOwner(typeof(SecurityIdentifier)));
        Assert.True(security.AreAccessRulesProtected);
        const FileSystemRights write = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete | FileSystemRights.ChangePermissions;
        foreach (var dir in new[] { data, Path.Combine(data, "Reports") })
            foreach (FileSystemAccessRule rule in new DirectoryInfo(dir).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.IdentityReference == Users || rule.IdentityReference.Value == "S-1-1-0" || rule.IdentityReference.Value == "S-1-3-0")
                    Assert.True((rule.FileSystemRights & write) == 0, $"{dir}: {rule.IdentityReference} darf schreiben");
    }

    [Fact]
    public void Secure_ReplacesFolderOwnedByUser()
    {
        if (!SystemEnv.IsElevated) return;

        string data = Path.Combine(_root, "data");
        Directory.CreateDirectory(data);
        File.WriteAllText(Path.Combine(data, "undo.json"), "[]");
        SetOwner(new DirectoryInfo(data), WindowsIdentity.GetCurrent().User!);

        var setAside = new List<string>();
        AppPaths.Secure(data, setAside);

        Assert.Single(setAside);
        Assert.False(File.Exists(Path.Combine(data, "undo.json")));
        Assert.True(File.Exists(Path.Combine(setAside[0], "undo.json")));
        Assert.Equal(Admins, new DirectoryInfo(data).GetAccessControl().GetOwner(typeof(SecurityIdentifier)));
    }

    private static void SetOwner(FileSystemInfo entry, SecurityIdentifier owner)
    {
        if (entry is DirectoryInfo d)
        {
            var s = d.GetAccessControl();
            s.SetOwner(owner);
            d.SetAccessControl(s);
        }
        else
        {
            var f = (FileInfo)entry;
            var s = f.GetAccessControl();
            s.SetOwner(owner);
            f.SetAccessControl(s);
        }
    }

    private static void Run(string exe, string args)
    {
        using var p = Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true })!;
        p.WaitForExit();
        Assert.Equal(0, p.ExitCode);
    }
}
