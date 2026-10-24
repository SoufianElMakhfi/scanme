using System.Text.Json;
using System.Text.RegularExpressions;
using ScanMe.Core.Actions;
using KCmd = ScanMe.Core.Knowledge.CommandLineRules;
using KSig = ScanMe.Core.Knowledge.ContentSignatures;
using KTools = ScanMe.Core.Knowledge.KnownTools;

namespace ScanMe.Core.Updates;

/// <summary>
/// Haelt die zusaetzlich geladenen (signierten) Online-Regeln und stellt sie den Scannern bereit.
/// Laedt beim Start die zuletzt gueltige, lokal gespeicherte Version.
/// </summary>
public static class RuleStore
{
    private static readonly object Sync = new();
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    public static string CacheFile => Path.Combine(AppPaths.DataDir, "rules.json");
    public static string CacheSignature => CacheFile + ".sig";

    public static int Version { get; private set; }
    public static string? Published { get; private set; }

    public static IReadOnlyList<KCmd.Rule> CommandLineRules { get; private set; } = [];
    public static IReadOnlyList<KSig.Signature> ContentSignatures { get; private set; } = [];
    public static IReadOnlyList<(Regex Name, Version? FixedIn, int Weight, string Text)> VulnerableSoftware { get; private set; } = [];
    public static IReadOnlyDictionary<string, string> VulnerableDrivers { get; private set; } = new Dictionary<string, string>();
    public static IReadOnlyList<KTools.Tool> KnownTools { get; private set; } = [];

    static RuleStore() => LoadCached();

    /// <summary>Laedt die lokal gespeicherte Regeldatei – nur wenn ihre Signatur gueltig ist.</summary>
    public static void LoadCached()
    {
        try
        {
            if (!File.Exists(CacheFile) || !File.Exists(CacheSignature)) return;
            byte[] data = File.ReadAllBytes(CacheFile);
            if (!RuleSigning.Verify(data, File.ReadAllText(CacheSignature))) return;
            Apply(Parse(data));
        }
        catch { /* defekte Datei -> nur eingebaute Regeln */ }
    }

    public static RuleSet Parse(byte[] data) =>
        JsonSerializer.Deserialize<RuleSet>(data, new JsonSerializerOptions { ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true })
        ?? throw new InvalidDataException("Leeres Regelpaket.");

    /// <summary>Uebernimmt ein (bereits verifiziertes) Regelpaket. Gewichte werden begrenzt, ungueltige Eintraege ignoriert.</summary>
    public static void Apply(RuleSet set)
    {
        static int Clamp(int w) => Math.Clamp(w, 0, 90);

        var cmd = new List<KCmd.Rule>();
        foreach (var r in set.CommandLineRules)
        {
            try
            {
                var regex = new Regex(r.Pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
                cmd.Add(new KCmd.Rule("NET_" + r.Id, regex, Clamp(r.Weight), r.Text, r.Mitre));
            }
            catch (ArgumentException) { }
        }

        var sigs = set.ContentSignatures
            .Where(s => s.Patterns.Count > 0 && s.Patterns.All(p => p.Length >= 4)) // zu kurze Muster erzeugen Zufallstreffer
            .Select(s => new KSig.Signature(s.Name, s.Family, Clamp(s.Weight), Math.Max(1, s.MinHits),
                Enum.TryParse<KSig.Target>(s.AppliesTo, true, out var t) ? t : KSig.Target.Any,
                s.Patterns.ToArray(), s.Explanation))
            .ToList();

        var vuln = new List<(Regex, Version?, int, string)>();
        foreach (var v in set.VulnerableSoftware)
        {
            try
            {
                vuln.Add((new Regex(v.NamePattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout),
                    v.FixedIn != null ? System.Version.Parse(v.FixedIn) : null, Clamp(v.Weight), v.Text));
            }
            catch { }
        }

        var tools = set.KnownTools
            .Where(t => t.ProcessNames.Count > 0)
            .Select(t => new KTools.Tool(t.Name, Enum.TryParse<KTools.ToolKind>(t.Kind, true, out var k) ? k : KTools.ToolKind.RemoteAccess,
                t.ProcessNames.ToArray(), t.Note))
            .ToList();

        lock (Sync)
        {
            CommandLineRules = cmd;
            ContentSignatures = sigs;
            VulnerableSoftware = vuln;
            VulnerableDrivers = new Dictionary<string, string>(set.VulnerableDrivers, StringComparer.OrdinalIgnoreCase);
            KnownTools = tools;
            Version = set.Version;
            Published = set.Published;
        }
    }
}
