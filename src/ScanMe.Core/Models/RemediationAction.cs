namespace ScanMe.Core.Models;

public enum RemediationKind
{
    OpenLocation,
    KillProcess,
    QuarantineFile,
    DisableAutostart,
    DisableScheduledTask,
    DisableService,
    RemoveWmiSubscription,
    DeleteRegistryValue,
    RestoreRegistryValue,
    RemoveDefenderExclusion,
    RestoreHostsFile,
    DefenderScanFile,
    LookupOnline,
}

/// <summary>Eine moegliche Gegenmassnahme zu einem Fund.</summary>
public sealed class RemediationAction
{
    public required RemediationKind Kind { get; init; }
    public required string Label { get; init; }

    /// <summary>Datei, Registry-Pfad, Taskname, Dienstname oder PID – je nach Kind.</summary>
    public string? Target { get; init; }

    /// <summary>Zusatzdaten, z. B. Registry-Wertname.</summary>
    public string? Argument { get; init; }

    /// <summary>Destruktive Aktionen verlangen eine Bestaetigung in der UI.</summary>
    public bool RequiresConfirmation { get; init; } = true;
}
