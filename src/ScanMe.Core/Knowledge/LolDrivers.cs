using System.Text.Json;
using System.Text.Json.Serialization;

namespace ScanMe.Core.Knowledge;

/// <summary>
/// Bekannt verwundbare und boesartige Treiber aus LOLDrivers (https://www.loldrivers.io, Apache-2.0).
/// Abgleich nur ueber Fingerabdruecke: Dateinamen lassen sich faelschen, und von vielen Treibern ist nur
/// eine bestimmte, alte Version verwundbar. Aktualisierung: tools/update-loldrivers.ps1.
/// Die Liste liegt als Data\loldrivers.json neben der EXE (siehe ScanMe.Core.csproj, warum nicht eingebettet).
/// </summary>
public static class LolDrivers
{
    public sealed class Entry
    {
        [JsonPropertyName("id")] public string Id { get; set; } = "";
        [JsonPropertyName("category")] public string Category { get; set; } = "vulnerable";
        [JsonPropertyName("names")] public List<string> Names { get; set; } = new();
        [JsonPropertyName("cves")] public List<string> Cves { get; set; } = new();
        [JsonPropertyName("sha256")] public List<string> Sha256 { get; set; } = new();
        [JsonPropertyName("authentihash")] public List<string> Authentihash { get; set; } = new();

        public bool IsMalicious => Category == "malicious";
        public string Url => $"https://www.loldrivers.io/drivers/{Id}/";

        public string Describe() =>
            (Names.Count > 0 ? string.Join(", ", Names.Take(3)) : "unbenannter Treiber") + (Cves.Count > 0 ? $" ({string.Join(", ", Cves.Take(3))})" : "");
    }

    private sealed class Data
    {
        [JsonPropertyName("generated")] public string? Generated { get; set; }
        [JsonPropertyName("drivers")] public List<Entry> Drivers { get; set; } = new();
    }

    private static readonly Lazy<(Dictionary<string, Entry> Sha, Dictionary<string, Entry> Auth, string? Generated)> Loaded = new(Load);

    public static string DataFile => Path.Combine(AppContext.BaseDirectory, "Data", "loldrivers.json");

    public static int Count => Loaded.Value.Sha.Values.Concat(Loaded.Value.Auth.Values).Distinct().Count();
    public static string? Generated => Loaded.Value.Generated;

    private static (Dictionary<string, Entry>, Dictionary<string, Entry>, string?) Load()
    {
        var sha = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        var auth = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (!File.Exists(DataFile)) return (sha, auth, null);
            using var s = File.OpenRead(DataFile);
            var file = JsonSerializer.Deserialize<Data>(s);
            foreach (var e in file?.Drivers ?? [])
            {
                foreach (var h in e.Sha256) sha.TryAdd(h, e);
                foreach (var h in e.Authentihash) auth.TryAdd(h, e);
            }
            return (sha, auth, file?.Generated);
        }
        catch { return (sha, auth, null); }
    }

    /// <summary>Exakt dieselbe Datei (SHA256).</summary>
    public static Entry? FindBySha256(string? sha256) =>
        sha256 != null && Loaded.Value.Sha.TryGetValue(sha256, out var e) ? e : null;

    /// <summary>Derselbe Programmcode, auch umbenannt oder neu signiert (Authentihash).</summary>
    public static Entry? FindByAuthentihash(string? hash) =>
        hash != null && Loaded.Value.Auth.TryGetValue(hash, out var e) ? e : null;

    /// <summary>Erst ueber den (meist schon berechneten) SHA256, sonst ueber den Authentihash.</summary>
    public static Entry? Find(string path, string? sha256) =>
        FindBySha256(sha256) ?? FindByAuthentihash(Inventory.PeFile.AuthenticodeSha256(path));
}
