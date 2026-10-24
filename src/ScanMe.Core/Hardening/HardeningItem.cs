namespace ScanMe.Core.Hardening;

public enum HardeningState { Unknown, Off, Audit, On, NotAvailable }

public enum HardeningMode { Off, Audit, On }

/// <summary>Eine Schutzmassnahme mit verstaendlicher Erklaerung, Lese- und Schreibfunktion.</summary>
public sealed class HardeningItem
{
    public required string Id { get; init; }
    public required string Group { get; init; }
    public required string Title { get; init; }

    /// <summary>Was die Massnahme tut – in einfachen Worten.</summary>
    public required string Plain { get; init; }

    /// <summary>Wogegen sie schuetzt.</summary>
    public required string Protects { get; init; }

    /// <summary>Moegliche Nebenwirkung fuer Entwickler / Power-User (null = keine bekannt).</summary>
    public string? DevNote { get; init; }

    public bool SupportsAudit { get; init; }
    public bool NeedsReboot { get; init; }

    /// <summary>Empfohlene Stufe fuer "Empfohlene Einstellungen anwenden". Null = nur auf ausdruecklichen Wunsch.</summary>
    public HardeningMode? Recommended { get; init; }

    public required Func<HardeningState> Read { get; init; }

    /// <summary>Setzt die Stufe. Rueckgabe: Fehlermeldung oder null.</summary>
    public required Func<HardeningMode, string?> Apply { get; init; }
}
