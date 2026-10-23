using System.Text.RegularExpressions;

namespace ScanMe.Core.Util;

public static partial class PathUtil
{
    public static readonly string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    public static readonly string System32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
    public static readonly string SysWow64 = Path.Combine(WindowsDir, "SysWOW64");
    public static readonly string ProgramFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    public static readonly string ProgramFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    public static readonly string ProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
    public static readonly string UsersRoot = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) ?? @"C:\Users";

    private static readonly string[] ExecutableExtensions = [".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".cpl", ".msi", ".lnk", ".ocx", ".pif"];

    public static string Normalize(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "";
        path = path.Trim().Trim('"');
        path = Environment.ExpandEnvironmentVariables(path);

        if (path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path[4..];
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) path = path[4..];
        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            path = Path.Combine(WindowsDir, path[12..]);
        else if (path.StartsWith(@"SystemRoot\", StringComparison.OrdinalIgnoreCase))
            path = Path.Combine(WindowsDir, path[11..]);
        else if (path.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase))
            path = Path.Combine(WindowsDir, path);

        try { return Path.GetFullPath(path); }
        catch { return path; }
    }

    public static bool IsUnder(string path, string root) =>
        !string.IsNullOrEmpty(path) && !string.IsNullOrEmpty(root)
        && path.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);

    public static bool IsUnderWindowsDirectory(string path) => IsUnder(path, WindowsDir);

    public static bool IsInSystemDirectory(string path) => IsUnder(path, System32) || IsUnder(path, SysWow64);

    public static bool IsUnderProgramFiles(string path) => IsUnder(path, ProgramFiles) || IsUnder(path, ProgramFilesX86);

    public static bool LooksExecutable(string path) =>
        ExecutableExtensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Ermittelt aus einer Kommandozeile (Autostart, Dienst, Task) die eigentlich ausgefuehrte Datei.
    /// Bei Hosts wie rundll32/regsvr32/wscript/mshta wird zusaetzlich die Nutzlast-Datei geliefert.
    /// </summary>
    public static (string? Executable, string? Payload) ResolveCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return (null, null);
        string cmd = Environment.ExpandEnvironmentVariables(commandLine.Trim());

        string? exe;
        string rest;
        if (cmd.StartsWith('"'))
        {
            int end = cmd.IndexOf('"', 1);
            exe = end > 1 ? cmd[1..end] : cmd.Trim('"');
            rest = end > 0 && end + 1 < cmd.Length ? cmd[(end + 1)..].Trim() : "";
        }
        else
        {
            // Unquotierte Pfade mit Leerzeichen: schrittweise verlaengern, bis eine Datei existiert.
            exe = null;
            rest = "";
            var parts = cmd.Split(' ');
            for (int i = 1; i <= parts.Length; i++)
            {
                string candidate = string.Join(' ', parts.Take(i));
                string? found = FindExecutable(candidate);
                if (found != null)
                {
                    exe = found;
                    rest = string.Join(' ', parts.Skip(i));
                    break;
                }
            }
            if (exe == null)
            {
                exe = parts[0];
                rest = string.Join(' ', parts.Skip(1));
            }
        }

        string resolved = FindExecutable(exe) ?? Normalize(exe);
        string? payload = ResolvePayload(Path.GetFileName(resolved), rest);
        return (resolved, payload);
    }

    private static string? ResolvePayload(string host, string args)
    {
        if (string.IsNullOrWhiteSpace(args)) return null;
        host = host.ToLowerInvariant();
        if (host is not ("rundll32.exe" or "regsvr32.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe" or "powershell.exe" or "pwsh.exe" or "cmd.exe" or "msiexec.exe"))
            return null;

        foreach (Match m in FileArgRegex().Matches(args))
        {
            string candidate = m.Groups["q"].Success ? m.Groups["q"].Value : m.Groups["u"].Value;
            candidate = candidate.Split(',')[0].Trim();
            if (candidate.StartsWith('/') || candidate.StartsWith('-')) continue;
            if (!LooksExecutable(candidate) && Path.GetExtension(candidate).Length == 0) continue;
            string? found = FindExecutable(candidate);
            if (found != null) return found;
        }
        return null;
    }

    /// <summary>Sucht eine Datei wie die Windows-Shell: absolut, mit .exe-Endung, in System32/PATH.</summary>
    public static string? FindExecutable(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        string n = Normalize(name);
        try
        {
            if (File.Exists(n)) return n;
            if (!Path.HasExtension(n) && File.Exists(n + ".exe")) return n + ".exe";
            if (Path.IsPathRooted(name.Trim('"'))) return null;

            string bare = name.Trim('"');
            var dirs = new List<string> { System32, WindowsDir };
            dirs.AddRange((Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries));
            foreach (var d in dirs)
            {
                try
                {
                    string p = Path.Combine(d, bare);
                    if (File.Exists(p)) return Path.GetFullPath(p);
                    if (!Path.HasExtension(p) && File.Exists(p + ".exe")) return Path.GetFullPath(p + ".exe");
                }
                catch { }
            }
        }
        catch { }
        return null;
    }

    [GeneratedRegex("\"(?<q>[^\"]+)\"|(?<u>[^\\s\"]+)")]
    private static partial Regex FileArgRegex();
}
