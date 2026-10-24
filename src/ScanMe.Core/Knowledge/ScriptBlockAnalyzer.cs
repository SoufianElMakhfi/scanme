using System.Text.RegularExpressions;

namespace ScanMe.Core.Knowledge;

/// <summary>
/// Analysiert protokollierte PowerShell-Skriptbloecke nach ihrer WIRKUNG statt nach Schluesselwoertern:
/// Nur tatsaechliche Aufrufe mit Parametern zaehlen, die Richtung (Schutz schwaechen/verbessern) wird beachtet,
/// und automatisch erzeugter Modulcode (CDXML/Cmdletization, z. B. das Defender-Modul) wird erkannt.
/// </summary>
public static partial class ScriptBlockAnalyzer
{
    /// <summary>Ein Aufruf von Set-/Add-/Remove-MpPreference mit einem Parameter.</summary>
    public sealed record DefenderCall(string Cmdlet, string Parameter, string? Value, bool WeakensProtection)
    {
        public string Describe() => $"{Cmdlet} -{Parameter}" + (Value != null ? $" {Value}" : "");
    }

    /// <summary>
    /// Automatisch generierter Modulcode (z. B. beim Laden des Defender-Moduls) enthaelt Parameter-DEKLARATIONEN
    /// wie ${DisableRealtimeMonitoring}, aber keine Aufrufe – er ist kein Angriffsindiz.
    /// </summary>
    public static bool IsGeneratedModuleCode(string script) =>
        script.Contains("__cmdletization_", StringComparison.OrdinalIgnoreCase)
        || script.Contains("Microsoft.PowerShell.Cmdletization", StringComparison.OrdinalIgnoreCase)
        || script.Contains("CmdletizationClassName", StringComparison.OrdinalIgnoreCase);

    [GeneratedRegex(@"\b(?<cmd>Set|Add|Remove)-MpPreference\b(?<args>[^\r\n;|]*)", RegexOptions.IgnoreCase)]
    private static partial Regex MpPreferenceCall();

    [GeneratedRegex(@"(?:^|\s)-(?<p>[A-Za-z]+)(?::|\s+|$)(?<v>'[^']*'|""[^""]*""|[^\s-][^\s]*)?", RegexOptions.IgnoreCase)]
    private static partial Regex Parameter();

    [GeneratedRegex(@"\b[A-Z][a-z]+-[A-Z][A-Za-z]+\b")]
    private static partial Regex CmdletName();

    private static readonly HashSet<string> CommonParameters = new(StringComparer.OrdinalIgnoreCase)
    {
        "Force", "Verbose", "Debug", "ErrorAction", "WarningAction", "WhatIf", "Confirm", "CimSession", "ThrottleLimit", "AsJob",
    };

    /// <summary>Findet echte Defender-Konfigurationsaufrufe und bewertet, ob sie den Schutz schwaechen.</summary>
    public static List<DefenderCall> FindDefenderCalls(string script)
    {
        var calls = new List<DefenderCall>();
        if (IsGeneratedModuleCode(script)) return calls;

        foreach (Match m in MpPreferenceCall().Matches(script))
        {
            string cmdlet = $"{Capitalize(m.Groups["cmd"].Value)}-MpPreference";
            foreach (Match p in Parameter().Matches(m.Groups["args"].Value))
            {
                string name = p.Groups["p"].Value;
                if (CommonParameters.Contains(name)) continue;
                string? value = p.Groups["v"].Success ? p.Groups["v"].Value.Trim('\'', '"') : null;
                calls.Add(new DefenderCall(cmdlet, name, value, Weakens(cmdlet, name, value)));
            }
        }
        return calls;
    }

    private static bool Weakens(string cmdlet, string parameter, string? value)
    {
        bool exclusion = parameter.StartsWith("Exclusion", StringComparison.OrdinalIgnoreCase);
        if (cmdlet.StartsWith("Remove", StringComparison.OrdinalIgnoreCase)) return false; // Ausnahmen entfernen = Schutz besser
        if (exclusion) return true;                                                          // Add/Set -Exclusion... = Luecke
        if (parameter.StartsWith("Disable", StringComparison.OrdinalIgnoreCase))
            return value == null || value.Equals("$true", StringComparison.OrdinalIgnoreCase) || value == "1" || value.Equals("true", StringComparison.OrdinalIgnoreCase);
        if (parameter.Equals("MAPSReporting", StringComparison.OrdinalIgnoreCase) || parameter.Equals("SubmitSamplesConsent", StringComparison.OrdinalIgnoreCase))
            return value is "0" or "2" or "Disabled" or "NeverSend";
        return false;
    }

    /// <summary>Welche Cmdlets ruft der Skriptblock auf? (fuer eine verstaendliche Zusammenfassung)</summary>
    public static List<string> CalledCmdlets(string script, int max = 10) =>
        CmdletName().Matches(script).Select(m => m.Value).Distinct(StringComparer.OrdinalIgnoreCase).Take(max).ToList();

    private static string Capitalize(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..].ToLowerInvariant();
}
