using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using ScanMe.Core.Util;

namespace ScanMe.Core.Antivirus;

/// <summary>
/// Microsoft Defender ueber MpCmdRun.exe: einzelne Dateien oder ganze Ordner pruefen, ohne etwas zu entfernen.
/// So nutzt ScanMe Defenders komplette Signaturen und Cloud-Erkennung (inkl. Archivinhalten).
/// </summary>
public static partial class DefenderCli
{
    public sealed record Detection(string Threat, string Path, string? InnerPath);

    /// <param name="ExitCode">0 = nichts gefunden, 2 = Bedrohungen gefunden, sonst Fehler (z. B. Defender abgeschaltet).</param>
    public sealed record Result(int ExitCode, bool TimedOut, IReadOnlyList<Detection> Detections, string Output)
    {
        public bool Completed => !TimedOut && ExitCode is 0 or 2;
    }

    [GeneratedRegex(@"^\s*Threat\s*:\s*(?<name>.+?)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex ThreatLine();

    [GeneratedRegex(@"^\s*(?:file|containerfile)\s*:\s*(?<path>.+?)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex FileLine();

    public static string? Find()
    {
        try
        {
            string platform = Path.Combine(PathUtil.ProgramData, @"Microsoft\Windows Defender\Platform");
            if (Directory.Exists(platform))
            {
                // Versionsordner wie "4.18.26100.4-0" numerisch vergleichen, nicht als Text
                var newest = Directory.GetDirectories(platform)
                    .Select(d => (Exe: Path.Combine(d, "MpCmdRun.exe"), Version: PlatformVersion(Path.GetFileName(d))))
                    .Where(x => File.Exists(x.Exe))
                    .OrderByDescending(x => x.Version)
                    .FirstOrDefault();
                if (newest.Exe != null) return newest.Exe;
            }
        }
        catch { }
        string classic = Path.Combine(PathUtil.ProgramFiles, @"Windows Defender\MpCmdRun.exe");
        return File.Exists(classic) ? classic : null;
    }

    private static Version PlatformVersion(string dir)
    {
        int dash = dir.IndexOf('-');
        return Version.TryParse(dash > 0 ? dir[..dash] : dir, out var v) ? v : new Version(0, 0);
    }

    /// <summary>Prueft eine Datei mit Defender. Rueckgabe: Bedrohungsname oder null.</summary>
    public static string? ScanFile(string path, TimeSpan timeout)
    {
        var r = Scan(path, timeout);
        return r is { ExitCode: 2 } ? r.Detections.FirstOrDefault()?.Threat ?? "Bedrohung erkannt" : null;
    }

    /// <summary>
    /// Prueft eine Datei oder einen Ordner (rekursiv, inkl. Archiven) ohne Bereinigung.
    /// Null, wenn Defender nicht vorhanden ist. Bei Abbruch wird MpCmdRun beendet.
    /// </summary>
    public static Result? Scan(string path, TimeSpan timeout, CancellationToken ct = default)
    {
        string? mp = Find();
        if (mp == null) return null;
        var psi = new ProcessStartInfo(mp)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var a in new[] { "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation" }) psi.ArgumentList.Add(a);

        using var p = Process.Start(psi);
        if (p == null) return null;
        // Beide Stroeme parallel lesen: sonst blockiert MpCmdRun bei vollem Puffer und der Timeout greift nie.
        var stdout = new MemoryStream();
        var outTask = p.StandardOutput.BaseStream.CopyToAsync(stdout);
        var errTask = p.StandardError.ReadToEndAsync();

        var deadline = DateTime.UtcNow + timeout;
        while (!p.WaitForExit(250))
        {
            if (ct.IsCancellationRequested || DateTime.UtcNow > deadline)
            {
                try { p.Kill(entireProcessTree: true); } catch { }
                ct.ThrowIfCancellationRequested();
                return new Result(-1, true, [], "");
            }
        }
        try { Task.WaitAll([outTask, errTask], TimeSpan.FromSeconds(5)); } catch { }

        string output = Decode(stdout.ToArray());
        return new Result(p.ExitCode, false, ParseDetections(output), output);
    }

    /// <summary>MpCmdRun schreibt je nach Konsole UTF-8 oder die OEM-Codepage – ungueltiges UTF-8 heisst OEM.</summary>
    private static string Decode(byte[] bytes)
    {
        try { return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes); }
        catch (DecoderFallbackException)
        {
            try { return CodePagesEncoding.Get(CultureInfo.CurrentCulture.TextInfo.OEMCodePage).GetString(bytes); }
            catch { return Encoding.Latin1.GetString(bytes); }
        }
    }

    /// <summary>
    /// Liest den Block "LIST OF DETECTED THREATS": je Bedrohung eine Zeile "Threat : Name", darunter die
    /// betroffenen Dateien. Dateien in Archiven stehen als "archiv.zip->innen.exe".
    /// </summary>
    public static List<Detection> ParseDetections(string output)
    {
        var result = new List<Detection>();
        string? threat = null;
        foreach (var raw in output.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            var t = ThreatLine().Match(line);
            if (t.Success) { threat = t.Groups["name"].Value; continue; }
            if (threat == null) continue;
            var f = FileLine().Match(line);
            if (!f.Success) continue;
            string full = f.Groups["path"].Value;
            int arrow = full.IndexOf("->", StringComparison.Ordinal);
            string path = arrow > 0 ? full[..arrow] : full;
            string? inner = arrow > 0 ? full[(arrow + 2)..] : null;
            if (!result.Any(d => d.Threat == threat && d.Path.Equals(path, StringComparison.OrdinalIgnoreCase) && d.InnerPath == inner))
                result.Add(new Detection(threat, path, inner));
        }
        return result;
    }

    /// <summary>Unerwuenschte Programme (Werbung, Bundler) wiegen weniger als echte Schadsoftware.</summary>
    public static bool IsPuaName(string name) =>
        name.StartsWith("PUA", StringComparison.OrdinalIgnoreCase) || name.StartsWith("Adware", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("SoftwareBundler", StringComparison.OrdinalIgnoreCase) || name.StartsWith("BrowserModifier", StringComparison.OrdinalIgnoreCase);

    private static class CodePagesEncoding
    {
        static CodePagesEncoding() => Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        public static Encoding Get(int codePage) => Encoding.GetEncoding(codePage);
    }
}
