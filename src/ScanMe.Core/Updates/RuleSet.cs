using System.Text.Json.Serialization;

namespace ScanMe.Core.Updates;

/// <summary>
/// Online-Regelpaket (rules/rules.json im Repository). Regeln koennen Erkennungen nur HINZUFUEGEN –
/// eingebaute Regeln lassen sich darueber weder entfernen noch abschwaechen.
/// </summary>
public sealed class RuleSet
{
    [JsonPropertyName("version")] public int Version { get; set; }
    [JsonPropertyName("minAppVersion")] public string? MinAppVersion { get; set; }
    [JsonPropertyName("published")] public string? Published { get; set; }
    [JsonPropertyName("commandLineRules")] public List<CommandLineRuleDto> CommandLineRules { get; set; } = new();
    [JsonPropertyName("contentSignatures")] public List<ContentSignatureDto> ContentSignatures { get; set; } = new();
    [JsonPropertyName("vulnerableSoftware")] public List<VulnerableSoftwareDto> VulnerableSoftware { get; set; } = new();
    [JsonPropertyName("vulnerableDrivers")] public Dictionary<string, string> VulnerableDrivers { get; set; } = new();
    [JsonPropertyName("knownTools")] public List<KnownToolDto> KnownTools { get; set; } = new();
}

public sealed class CommandLineRuleDto
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("pattern")] public string Pattern { get; set; } = "";
    [JsonPropertyName("weight")] public int Weight { get; set; }
    [JsonPropertyName("text")] public string Text { get; set; } = "";
    [JsonPropertyName("mitre")] public string? Mitre { get; set; }
}

public sealed class ContentSignatureDto
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("family")] public string Family { get; set; } = "";
    [JsonPropertyName("weight")] public int Weight { get; set; }
    [JsonPropertyName("minHits")] public int MinHits { get; set; } = 1;
    [JsonPropertyName("appliesTo")] public string AppliesTo { get; set; } = "Any";
    [JsonPropertyName("patterns")] public List<string> Patterns { get; set; } = new();
    [JsonPropertyName("explanation")] public string Explanation { get; set; } = "";
}

public sealed class VulnerableSoftwareDto
{
    [JsonPropertyName("namePattern")] public string NamePattern { get; set; } = "";
    [JsonPropertyName("fixedIn")] public string? FixedIn { get; set; }
    [JsonPropertyName("weight")] public int Weight { get; set; }
    [JsonPropertyName("text")] public string Text { get; set; } = "";
}

public sealed class KnownToolDto
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("kind")] public string Kind { get; set; } = "RemoteAccess";
    [JsonPropertyName("processNames")] public List<string> ProcessNames { get; set; } = new();
    [JsonPropertyName("note")] public string Note { get; set; } = "";
}
