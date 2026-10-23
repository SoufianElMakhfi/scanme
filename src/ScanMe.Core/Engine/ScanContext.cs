using System.Collections.Concurrent;
using ScanMe.Core.Models;
using ScanMe.Core.Trust;
using ScanMe.Core.Util;

namespace ScanMe.Core.Engine;

public enum ScanProfile
{
    Quick,
    Full,
}

public sealed class ScanOptions
{
    public ScanProfile Profile { get; set; } = ScanProfile.Full;

    /// <summary>Microsoft Defender fuer verdaechtige Dateien zusaetzlich befragen.</summary>
    public bool UseDefender { get; set; } = true;

    /// <summary>Zusaetzliche Ordner fuer den Datei-Scan.</summary>
    public List<string> ExtraPaths { get; } = new();

    /// <summary>Wie viele Tage zurueck Ereignisprotokolle ausgewertet werden.</summary>
    public int EventLogDays { get; set; } = 30;

    /// <summary>Scanner-IDs, die uebersprungen werden sollen.</summary>
    public HashSet<string> DisabledScanners { get; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Gemeinsamer Zustand eines Scanlaufs. Scanner melden Funde ueber <see cref="Add"/>.</summary>
public sealed class ScanContext
{
    private readonly ConcurrentBag<Finding> _findings = new();
    private readonly ConcurrentDictionary<string, object> _shared = new();
    private readonly IProgress<ScanProgress>? _progress;

    public ScanContext(ScanOptions options, CancellationToken cancellation, IProgress<ScanProgress>? progress = null)
    {
        Options = options;
        Cancellation = cancellation;
        _progress = progress;
    }

    public ScanOptions Options { get; }
    public CancellationToken Cancellation { get; }
    public FileTrustService Trust { get; } = FileTrustService.Shared;
    public bool IsElevated { get; } = SystemEnv.IsElevated;
    public bool IsFullScan => Options.Profile == ScanProfile.Full;

    internal string CurrentScanner { get; set; } = "";
    internal int ScannerIndex { get; set; }
    internal int ScannerCount { get; set; }
    internal ScannerResult? CurrentResult { get; set; }

    public IReadOnlyCollection<Finding> Findings => _findings;

    public void Add(Finding f) => _findings.Add(f);

    public void Status(string message) =>
        _progress?.Report(new ScanProgress(CurrentScanner, ScannerIndex, ScannerCount, message));

    /// <summary>Hinweis im Scanprotokoll (z. B. "Ohne Adminrechte eingeschränkt").</summary>
    public void Note(string message) => CurrentResult?.Notes.Add(message);

    /// <summary>Teilt teure Daten (z. B. Prozessliste) zwischen Scannern.</summary>
    public T Shared<T>(string key, Func<T> factory) where T : notnull =>
        (T)_shared.GetOrAdd(key, _ => factory());

    public void ThrowIfCancelled() => Cancellation.ThrowIfCancellationRequested();
}
