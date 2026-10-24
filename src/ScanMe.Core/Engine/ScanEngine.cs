using System.Diagnostics;
using ScanMe.Core.Models;
using ScanMe.Core.Util;

namespace ScanMe.Core.Engine;

public sealed class ScanEngine
{
    private readonly IReadOnlyList<IScanner> _scanners;

    public ScanEngine(IEnumerable<IScanner> scanners) => _scanners = scanners.ToList();

    public IReadOnlyList<IScanner> Scanners => _scanners;

    public async Task<ScanReport> RunAsync(ScanOptions options, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
    {
        var report = new ScanReport
        {
            OsVersion = SystemEnv.OsDescription,
            WasElevated = SystemEnv.IsElevated,
        };
        var ctx = new ScanContext(options, ct, progress);

        var active = _scanners
            .Where(s => !options.DisabledScanners.Contains(s.Id))
            .Where(s => options.Profile == ScanProfile.Full || s.InQuickScan)
            .ToList();

        ctx.ScannerCount = active.Count;
        for (int i = 0; i < active.Count; i++)
        {
            var scanner = active[i];
            if (ct.IsCancellationRequested) { report.Cancelled = true; break; }

            var result = new ScannerResult { ScannerId = scanner.Id, ScannerName = scanner.Name };
            report.ScannerResults.Add(result);
            ctx.CurrentScanner = scanner.Name;
            ctx.ScannerIndex = i;
            ctx.CurrentResult = result;
            ctx.Status("Startet …");

            int before = ctx.Findings.Count;
            var sw = Stopwatch.StartNew();
            try
            {
                // Scanner laufen auf dem Threadpool, damit die UI fluessig bleibt.
                await Task.Run(() => scanner.ScanAsync(ctx), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                report.Cancelled = true;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }
            result.Duration = sw.Elapsed;
            result.FindingCount = ctx.Findings.Count - before;
        }

        foreach (var f in Deduplicate(ctx.Findings))
        {
            RiskScorer.Finalize(f);
            PlainLanguage.Apply(f);
            report.Findings.Add(f);
        }
        // Zuerst nach Laien-Ampel (Handeln vor Pruefen vor harmlos), dann nach technischem Score.
        report.Findings.Sort((a, b) =>
            a.Verdict != b.Verdict ? b.Verdict.CompareTo(a.Verdict)
            : b.Score != a.Score ? b.Score.CompareTo(a.Score)
            : string.Compare(a.Title, b.Title, StringComparison.CurrentCulture));
        report.FinishedAt = DateTime.Now;
        progress?.Report(new ScanProgress("", active.Count, active.Count, "Scan abgeschlossen"));
        return report;
    }

    private static IEnumerable<Finding> Deduplicate(IEnumerable<Finding> findings) =>
        findings
            .GroupBy(f => f.Fingerprint)
            .Select(g => g.OrderByDescending(f => f.Indicators.Sum(i => i.Weight)).First());
}
