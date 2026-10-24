using ScanMe.Core.Models;
using ScanMe.Core.Util;

namespace ScanMe.Core.Knowledge;

/// <summary>
/// Bewertet eine einzelne Defender-Ausnahme: Was verbirgt sie, und wie wahrscheinlich hat sie Malware angelegt?
/// </summary>
public static class ExclusionRisk
{
    private static readonly string[] BroadPaths =
    [
        @"c:\", @"c:\users", @"c:\windows", @"c:\programdata", @"%temp%", @"%appdata%", @"%localappdata%", @"\appdata", @"\temp",
        @"c:\users\public", @"\downloads", @"\desktop", "*", @"c:\program files", @"\appdata\local", @"\appdata\roaming",
    ];

    /// <summary>Begriffe in Ordner-/Dateinamen von Cheats, Cracks und Loadern – eine der haeufigsten Malware-Quellen.</summary>
    private static readonly string[] CheatKeywords =
    [
        "cheat", "loader", "inject", "hack", "crack", "keygen", "bypass", "spoofer", "executor", "aimbot", "wallhack", "esp ",
        "modmenu", "mod menu", "trainer", "kmspico", "activator", "ghax", "exloader", "unlocker", "skinchanger", "triggerbot",
    ];

    /// <param name="kind">"Pfad", "Prozess", "Dateiendung" oder "IP-Adresse".</param>
    /// <param name="quarantinedPaths">Originalpfade aller Dateien in der ScanMe-Quarantaene.</param>
    public static List<Indicator> Assess(string kind, string value, IEnumerable<string> quarantinedPaths)
    {
        var result = new List<Indicator>();
        string v = value.Trim().TrimEnd('\\').ToLowerInvariant();
        string expanded = PathUtil.Normalize(value).TrimEnd('\\');
        string fileName = Path.GetFileName(expanded);

        if (kind == "Dateiendung")
        {
            bool exe = v.TrimStart('.', '*') is "exe" or "dll" or "ps1" or "bat" or "cmd" or "vbs" or "js" or "scr" or "hta" or "msi";
            result.Add(new("EXCL_EXT", exe ? $"Alle Dateien mit Endung {value} sind vom Virenschutz ausgenommen" : $"Dateiendung {value} ausgenommen", exe ? 65 : 15));
            return result;
        }
        if (kind == "IP-Adresse")
        {
            result.Add(new("EXCL_IP", $"Netzwerkverkehr zu {value} wird nicht geprüft", 20));
            return result;
        }

        // --- Quarantaene: zeigt die Ausnahme auf bereits als Malware entfernte Dateien? ---
        var hits = quarantinedPaths.Where(q => q.Equals(expanded, StringComparison.OrdinalIgnoreCase)
                                               || PathUtil.IsUnder(q, expanded)
                                               || (kind == "Prozess" && Path.GetFileName(q).Equals(fileName, StringComparison.OrdinalIgnoreCase)))
                                   .ToList();
        if (hits.Count > 0)
            result.Add(new("EXCL_QUARANTINED", $"Zeigt auf Datei(en), die als Schadsoftware in Quarantäne liegen: {string.Join(", ", hits.Select(Path.GetFileName).Distinct().Take(3))}", 70));

        // --- Breite Ausnahmen ---
        if (kind == "Pfad" && BroadPaths.Any(b => v == b.TrimEnd('\\') || (b.StartsWith('\\') && v.EndsWith(b.TrimEnd('\\')))))
            result.Add(new("EXCL_BROAD", "Sehr weit gefasste Ausnahme – ganze Bereiche werden nicht geprüft", 60));
        if (kind == "Prozess" && Engine.ExecutableAssessor.LolBins.Contains(fileName))
            result.Add(new("EXCL_LOLBIN", $"Windows-Werkzeug {fileName} ist ausgenommen – damit läuft beliebiger Code ungeprüft", 60));

        // --- Imitierte Systemdateien ("Runtime Broker.exe" in AppData) ---
        if (fileName.Contains('.') && !PathUtil.IsInSystemDirectory(expanded))
        {
            string? lookalike = SystemProcesses.FindLookalike(fileName) ?? (SystemProcesses.Get(fileName) != null ? fileName : null);
            if (lookalike != null)
                result.Add(new("EXCL_MASQUERADE", $"Name imitiert die Windows-Datei {lookalike}, liegt aber nicht im Systemordner", 50));
        }

        // --- Cheats / Cracks / Loader ---
        string lower = expanded.ToLowerInvariant();
        string? keyword = CheatKeywords.FirstOrDefault(k => lower.Contains(k));
        if (keyword != null)
            result.Add(new("EXCL_CHEAT", $"Pfad deutet auf Cheat-/Crack-/Loader-Software hin (\"{keyword.Trim()}\") – häufiger Weg, auf dem Miner und Passwortdiebe auf den PC kommen", 35));

        // --- Ort ---
        var loc = LocationClassifier.Classify(expanded + (kind == "Pfad" && !Path.HasExtension(expanded) ? "\\x" : ""));
        if (LocationClassifier.IsUserWritable(loc))
            result.Add(new("EXCL_USERPATH", "Ausnahme in einem ohne Adminrechte beschreibbaren Benutzerordner", 25));

        // --- Verwaist ---
        if (kind == "Pfad" && !File.Exists(expanded) && !Directory.Exists(expanded) && !expanded.Contains('*') && !expanded.Contains('%'))
            result.Add(new("EXCL_ORPHANED", "Der ausgenommene Pfad existiert nicht mehr (Überbleibsel – wird z. B. bei Neuinstallation der Malware wieder wirksam)", 15));

        if (result.Count == 0)
            result.Add(new("EXCL_OTHER", "Ausnahme vorhanden", 10));
        return result;
    }
}
