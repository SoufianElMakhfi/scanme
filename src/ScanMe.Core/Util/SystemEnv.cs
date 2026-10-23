using System.Security.Principal;
using Microsoft.Win32;

namespace ScanMe.Core.Util;

public static class SystemEnv
{
    public static bool IsElevated
    {
        get
        {
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }

    public static string OsDescription
    {
        get
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                string product = key?.GetValue("ProductName") as string ?? "Windows";
                string display = key?.GetValue("DisplayVersion") as string ?? key?.GetValue("ReleaseId") as string ?? "";
                string build = key?.GetValue("CurrentBuild") as string ?? "";
                object? ubr = key?.GetValue("UBR");
                // ProductName meldet auf Windows 11 weiterhin "Windows 10" – Build >= 22000 ist Windows 11.
                if (int.TryParse(build, out var b) && b >= 22000)
                    product = product.Replace("Windows 10", "Windows 11");
                return $"{product} {display} (Build {build}{(ubr != null ? "." + ubr : "")})".Trim();
            }
            catch { return Environment.OSVersion.VersionString; }
        }
    }

    public static int BuildNumber => Environment.OSVersion.Version.Build;

    /// <summary>Alle Benutzerprofilordner (fuer Scans ueber alle Benutzer hinweg).</summary>
    public static IEnumerable<string> UserProfiles()
    {
        string root = PathUtil.UsersRoot;
        IEnumerable<string> dirs;
        try { dirs = Directory.GetDirectories(root); }
        catch { yield break; }

        foreach (var d in dirs)
        {
            string name = Path.GetFileName(d);
            if (name.Equals("Default", StringComparison.OrdinalIgnoreCase)
                || name.Equals("Default User", StringComparison.OrdinalIgnoreCase)
                || name.Equals("All Users", StringComparison.OrdinalIgnoreCase))
                continue;
            if (File.Exists(Path.Combine(d, "NTUSER.DAT")) || name.Equals("Public", StringComparison.OrdinalIgnoreCase))
                yield return d;
        }
    }
}
