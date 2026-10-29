namespace ScanMe.Core.Models;

public enum CheckResult
{
    /// <summary>Die Pruefung haelt die Datei fuer schaedlich.</summary>
    Bad,
    /// <summary>Auffaellig, aber kein Beleg fuer Schadsoftware (z. B. unerwuenschtes Programm).</summary>
    Warning,
    /// <summary>Geprueft, nichts gefunden.</summary>
    Good,
    /// <summary>Nur zur Einordnung, spricht weder dafuer noch dagegen.</summary>
    Neutral,
}

/// <summary>Ergebnis einer unabhaengigen Pruefung eines Fundes, z. B. "Microsoft Defender: keine Bedrohung erkannt".</summary>
public sealed record Check(string Source, CheckResult Result, string Text)
{
    public const string Defender = "Microsoft Defender";
    public const string Yara = "YARA-Regeln";
    public const string Signature = "Digitale Signatur";
    /// <summary>Praefix fuer andere ueber AMSI befragte Virenschutzprogramme.</summary>
    public const string OtherAntivirus = "Virenschutz";

    private const string PuaPrefix = "stuft das als unerwünschtes Programm ein: ";

    public string Symbol => Result switch
    {
        CheckResult.Bad => "✖",
        CheckResult.Warning => "!",
        CheckResult.Good => "✔",
        _ => "–",
    };

    public bool IsAntivirus => Source == Defender || Source.StartsWith(OtherAntivirus, StringComparison.Ordinal);

    /// <summary>Potenziell unerwuenschtes Programm (Werbung, Toolbars, Hacktools) – Warnung, kein Malware-Treffer.</summary>
    public bool IsPua => Text.StartsWith(PuaPrefix, StringComparison.Ordinal);

    /// <summary>Treffer eines Virenschutzes; PUA zaehlt nur als Warnung.</summary>
    public static Check Detection(string source, string threat, bool pua) =>
        new(source, pua ? CheckResult.Warning : CheckResult.Bad, (pua ? PuaPrefix : "erkennt Schadsoftware: ") + threat);
}
