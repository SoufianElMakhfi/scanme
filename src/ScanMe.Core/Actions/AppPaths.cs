namespace ScanMe.Core.Actions;

/// <summary>Ablageorte fuer Quarantaene, Rueckgaengig-Journal, Ignorierliste und Berichte.</summary>
public static class AppPaths
{
    private static readonly Lazy<string> Root = new(() =>
    {
        // Bevorzugt maschinenweit (App laeuft als Admin), sonst pro Benutzer.
        foreach (var baseDir in new[] { Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) })
        {
            try
            {
                string dir = Path.Combine(baseDir, "ScanMe");
                Directory.CreateDirectory(dir);
                string probe = Path.Combine(dir, ".probe");
                File.WriteAllText(probe, "");
                File.Delete(probe);
                return dir;
            }
            catch { }
        }
        return Path.Combine(Path.GetTempPath(), "ScanMe");
    });

    public static string DataDir => Root.Value;
    public static string QuarantineDir => Ensure(Path.Combine(DataDir, "Quarantine"));
    public static string BackupDir => Ensure(Path.Combine(DataDir, "Backups"));
    public static string ReportsDir => Ensure(Path.Combine(DataDir, "Reports"));
    public static string UndoJournal => Path.Combine(DataDir, "undo.json");
    public static string IgnoreFile => Path.Combine(DataDir, "ignored.json");
    public static string SettingsFile => Path.Combine(DataDir, "settings.json");

    private static string Ensure(string dir)
    {
        Directory.CreateDirectory(dir);
        return dir;
    }
}
