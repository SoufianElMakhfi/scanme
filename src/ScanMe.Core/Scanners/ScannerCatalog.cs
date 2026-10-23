using ScanMe.Core.Engine;

namespace ScanMe.Core.Scanners;

public static class ScannerCatalog
{
    /// <summary>Alle Scanner in sinnvoller Reihenfolge (Prozesse zuerst – andere nutzen deren Snapshot).</summary>
    public static IReadOnlyList<IScanner> CreateAll() =>
    [
        new ProcessScanner(),
        new PersistenceScanner(),
        new NetworkScanner(),
        new SecurityConfigScanner(),
        new AccountScanner(),
        new SoftwareScanner(),
        new BrowserScanner(),
        new DriverScanner(),
        new EventLogScanner(),
        new CompatibilityScanner(),
        new FileSystemScanner(),
        // Muss zuletzt laufen: vertieft die Funde aller anderen Scanner.
        new MalwareScanner(),
    ];
}
