namespace ScanMe.Core.Util;

/// <summary>
/// Erkennt ScanMe selbst (GUI und CLI im eigenen Programmordner), damit sich das Tool nicht als Fund meldet.
/// Abgleich ueber den exakten Pfad – nicht ueber Namen oder Metadaten, die Malware faelschen koennte.
/// </summary>
public static class SelfIdentity
{
    private static readonly HashSet<string> OwnFiles = BuildOwnFiles();

    private static HashSet<string> BuildOwnFiles()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (Environment.ProcessPath is { } self) set.Add(Path.GetFullPath(self));
        foreach (var name in new[] { "ScanMe.exe", "scanme-cli.exe", "ScanMe.dll", "scanme-cli.dll", "ScanMe.Core.dll" })
        {
            string p = Path.Combine(AppContext.BaseDirectory, name);
            if (File.Exists(p)) set.Add(Path.GetFullPath(p));
        }
        return set;
    }

    public static bool IsOwnFile(string? path) => path != null && OwnFiles.Contains(path);

    public static bool IsOwnProcess(int pid, string? imagePath) => pid == Environment.ProcessId || IsOwnFile(imagePath);
}
