using ScanMe.Core.Engine;

namespace ScanMe.Core.Scanners;

public static class ScannerCatalog
{
    /// <summary>Alle Scanner in sinnvoller Reihenfolge (Prozesse zuerst – andere nutzen deren Snapshot).</summary>
    public static IReadOnlyList<IScanner> CreateAll() =>
    [
        new ProcessScanner(),
    ];
}
