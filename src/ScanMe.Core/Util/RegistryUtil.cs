using Microsoft.Win32;

namespace ScanMe.Core.Util;

public static class RegistryUtil
{
    /// <summary>Oeffnet einen Schluessel anhand eines vollstaendigen Pfads wie "HKLM\SOFTWARE\...".</summary>
    public static RegistryKey? Open(string fullPath, bool writable = false)
    {
        var (root, sub) = Split(fullPath);
        if (root == null) return null;
        try { return root.OpenSubKey(sub, writable); }
        catch { return null; }
    }

    public static (RegistryKey? Root, string SubKey) Split(string fullPath)
    {
        int idx = fullPath.IndexOf('\\');
        string hive = idx < 0 ? fullPath : fullPath[..idx];
        string sub = idx < 0 ? "" : fullPath[(idx + 1)..];
        RegistryKey? root = hive.ToUpperInvariant() switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64),
            "HKCU" or "HKEY_CURRENT_USER" => RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64),
            "HKU" or "HKEY_USERS" => RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64),
            "HKCR" or "HKEY_CLASSES_ROOT" => RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, RegistryView.Registry64),
            _ => null,
        };
        return (root, sub);
    }

    public static object? GetValue(string fullPath, string name)
    {
        using var key = Open(fullPath);
        try { return key?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames); }
        catch { return null; }
    }

    public static string? GetString(string fullPath, string name) => GetValue(fullPath, name) switch
    {
        string s => s,
        string[] arr => string.Join(" ", arr),
        null => null,
        var o => o.ToString(),
    };

    public static int? GetInt(string fullPath, string name) => GetValue(fullPath, name) switch
    {
        int i => i,
        long l => (int)l,
        _ => null,
    };

    public static IEnumerable<(string Name, object? Value)> Values(string fullPath)
    {
        using var key = Open(fullPath);
        if (key == null) yield break;
        string[] names;
        try { names = key.GetValueNames(); } catch { yield break; }
        foreach (var n in names)
        {
            object? v;
            try { v = key.GetValue(n, null, RegistryValueOptions.DoNotExpandEnvironmentNames); } catch { continue; }
            yield return (n, v);
        }
    }

    public static string[] SubKeys(string fullPath)
    {
        using var key = Open(fullPath);
        try { return key?.GetSubKeyNames() ?? []; }
        catch { return []; }
    }

    /// <summary>Letzte Aenderung eines Schluessels. Gilt fuer den ganzen Schluessel, Windows speichert keine Zeit pro Wert.</summary>
    public static DateTime? LastWriteTime(string fullPath)
    {
        using var key = Open(fullPath);
        if (key == null) return null;
        try
        {
            var z = IntPtr.Zero;
            return Native.NativeMethods.RegQueryInfoKey(key.Handle, z, z, z, z, z, z, z, z, z, z, out long ft) == 0 ? DateTime.FromFileTime(ft) : null;
        }
        catch { return null; }
    }

    /// <summary>Alle geladenen Benutzer-Hives (angemeldete Benutzer) als "HKU\SID".</summary>
    public static IEnumerable<string> LoadedUserHives()
    {
        foreach (var sid in SubKeys("HKU"))
        {
            if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
            if (sid is ".DEFAULT" or "S-1-5-18" or "S-1-5-19" or "S-1-5-20") continue;
            yield return "HKU\\" + sid;
        }
    }

    public static string SidToUser(string sid)
    {
        try
        {
            return new System.Security.Principal.SecurityIdentifier(sid)
                .Translate(typeof(System.Security.Principal.NTAccount)).Value;
        }
        catch { return sid; }
    }
}
