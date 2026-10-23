using System.Text.Json;
using ScanMe.Core.Models;

namespace ScanMe.Core.Actions;

/// <summary>Funde, die der Benutzer als bekannt/gewollt markiert hat. Abgleich ueber den Fingerprint.</summary>
public static class IgnoreList
{
    private static readonly object Sync = new();
    private static HashSet<string>? _cache;

    public static HashSet<string> Load()
    {
        lock (Sync)
        {
            if (_cache != null) return _cache;
            try
            {
                _cache = File.Exists(AppPaths.IgnoreFile)
                    ? JsonSerializer.Deserialize<HashSet<string>>(File.ReadAllText(AppPaths.IgnoreFile)) ?? new()
                    : new();
            }
            catch { _cache = new(); }
            return _cache;
        }
    }

    public static bool IsIgnored(Finding f) => Load().Contains(f.Fingerprint);

    public static void Set(Finding f, bool ignored)
    {
        lock (Sync)
        {
            var set = Load();
            if (ignored) set.Add(f.Fingerprint); else set.Remove(f.Fingerprint);
            File.WriteAllText(AppPaths.IgnoreFile, JsonSerializer.Serialize(set));
        }
    }
}
