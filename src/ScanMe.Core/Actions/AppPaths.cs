using System.Security.AccessControl;
using System.Security.Principal;
using ScanMe.Core.Util;

namespace ScanMe.Core.Actions;

/// <summary>Ablageorte fuer Quarantaene, Rueckgaengig-Journal, Ignorierliste und Berichte.</summary>
public static class AppPaths
{
    public const string UntrustedDirName = "Untrusted";

    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    private static readonly List<string> SetAsideList = new();

    private static readonly Lazy<string> Root = new(() =>
    {
        // Mit Adminrechten maschinenweit. In ProgramData duerfen normale Benutzer aber Dateien anlegen – ungesichert
        // koennte jeder Prozess ScanMe (das als Admin laeuft) eine Aufraeumliste, ein Rueckgaengig-Journal oder einen
        // Quarantaene-Eintrag unterschieben. Der Ordner wird daher abgesichert; ohne Adminrechte: pro Benutzer.
        if (SystemEnv.IsElevated)
            return Secure(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ScanMe"), SetAsideList);
        try
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ScanMe");
            Directory.CreateDirectory(dir);
            return dir;
        }
        catch
        {
            return Path.Combine(Path.GetTempPath(), "ScanMe");
        }
    });

    public static string DataDir => Root.Value;
    public static string QuarantineDir => Ensure(Path.Combine(DataDir, "Quarantine"));
    public static string BackupDir => Ensure(Path.Combine(DataDir, "Backups"));
    public static string ReportsDir => Ensure(Path.Combine(DataDir, "Reports"));
    public static string UndoJournal => Path.Combine(DataDir, "undo.json");
    public static string IgnoreFile => Path.Combine(DataDir, "ignored.json");
    public static string SettingsFile => Path.Combine(DataDir, "settings.json");

    /// <summary>Beim Absichern beiseitegelegte Eintraege (nicht von SYSTEM/Administratoren angelegt) – dem Nutzer anzeigen.</summary>
    public static IReadOnlyList<string> SetAside
    {
        get
        {
            _ = Root.Value;
            return SetAsideList;
        }
    }

    private static string Ensure(string dir)
    {
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>
    /// Sichert einen Datenordner ab (braucht Adminrechte): Besitzer Administratoren, nur SYSTEM und Administratoren duerfen
    /// schreiben, Benutzer nur lesen. Was nicht SYSTEM/Administratoren gehoert oder ein Link ist, wird nach
    /// <see cref="UntrustedDirName"/> verschoben und nie gelesen.
    /// </summary>
    public static string Secure(string dir, List<string>? setAside = null)
    {
        dir = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dir));
        string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        if (Exists(dir) && !IsTrusted(dir))
        {
            // Von einem Benutzer angelegt: Ihm gehoert der Ordner, er koennte ihn jederzeit austauschen (etwa gegen einen
            // Link auf einen Systemordner). Daher komplett beiseitelegen – nur verschieben, nie hineinschauen – und neu anlegen.
            string old = $"{dir}.untrusted-{stamp}";
            Move(dir, old);
            setAside?.Add(old);
        }

        var security = new DirectorySecurity();
        security.SetOwner(Admins);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var (sid, rights) in new[] { (LocalSystem, FileSystemRights.FullControl), (Admins, FileSystemRights.FullControl), (Users, FileSystemRights.ReadAndExecute) })
            security.AddAccessRule(new FileSystemAccessRule(sid, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        security.PurgeAccessRules(new SecurityIdentifier(WellKnownSidType.WorldSid, null));

        security.CreateDirectory(dir); // existiert er schon, bleibt er unveraendert – daher danach pruefen
        if (!IsTrusted(dir))
            throw new UnauthorizedAccessException($"Der Datenordner {dir} konnte nicht abgesichert werden – ein anderer Prozess verändert ihn gerade.");
        new DirectoryInfo(dir).SetAccessControl(security);

        SetAsideUntrusted(new DirectoryInfo(dir), dir, Path.Combine(dir, UntrustedDirName, stamp), setAside);
        return dir;
    }

    /// <summary>
    /// Durchlaeuft nur vertrauenswuerdige Ordner. Fremde Eintraege werden nur umbenannt (das folgt keinem Link) –
    /// ein Benutzer kann sie nicht mehr austauschen, weil er im abgesicherten Ordner keine Namen mehr anlegen darf.
    /// </summary>
    private static void SetAsideUntrusted(DirectoryInfo dir, string root, string target, List<string>? setAside)
    {
        foreach (var entry in dir.EnumerateFileSystemInfos())
        {
            if (dir.FullName.Equals(root, StringComparison.OrdinalIgnoreCase) && entry.Name.Equals(UntrustedDirName, StringComparison.OrdinalIgnoreCase)) continue;
            if (IsTrusted(entry.FullName))
            {
                RemoveExplicitRules(entry);
                if (entry is DirectoryInfo sub) SetAsideUntrusted(sub, root, target, setAside);
                continue;
            }
            string dst = Path.Combine(target, Path.GetRelativePath(root, entry.FullName));
            Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
            Move(entry.FullName, dst);
            setAside?.Add(dst);
        }
    }

    /// <summary>Gehoert SYSTEM oder den Administratoren und ist kein Link (Junction, Symlink).</summary>
    private static bool IsTrusted(string path)
    {
        try
        {
            var attributes = File.GetAttributes(path); // folgt keinem Link
            if ((attributes & FileAttributes.ReparsePoint) != 0) return false;
            FileSystemSecurity security = (attributes & FileAttributes.Directory) != 0
                ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner)
                : new FileInfo(path).GetAccessControl(AccessControlSections.Owner);
            var owner = security.GetOwner(typeof(SecurityIdentifier));
            return owner == Admins || owner == LocalSystem;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Nur die vom abgesicherten Ordner geerbten Rechte behalten.</summary>
    private static void RemoveExplicitRules(FileSystemInfo entry)
    {
        FileSystemSecurity security = entry is DirectoryInfo d ? d.GetAccessControl() : ((FileInfo)entry).GetAccessControl();
        var explicitRules = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier));
        if (explicitRules.Count == 0 && !security.AreAccessRulesProtected) return;
        foreach (FileSystemAccessRule rule in explicitRules) security.RemoveAccessRuleSpecific(rule);
        security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
        if (entry is DirectoryInfo dir) dir.SetAccessControl((DirectorySecurity)security);
        else ((FileInfo)entry).SetAccessControl((FileSecurity)security);
    }

    private static bool Exists(string path)
    {
        try
        {
            File.GetAttributes(path);
            return true;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return false;
        }
    }

    private static void Move(string src, string dst)
    {
        if ((File.GetAttributes(src) & FileAttributes.Directory) != 0) Directory.Move(src, dst);
        else File.Move(src, dst);
    }
}
