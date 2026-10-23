using ScanMe.Core.Models;

namespace ScanMe.Core.Engine;

public interface IScanner
{
    string Id { get; }
    string Name { get; }
    string Description { get; }

    /// <summary>Laeuft dieser Scanner im Schnellscan mit?</summary>
    bool InQuickScan { get; }

    Task ScanAsync(ScanContext ctx);
}
