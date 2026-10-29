using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ScanMe.Core.Antivirus;

public enum AmsiVerdict { Clean, Malware, BlockedByAdmin, Skipped }

/// <summary>
/// Fragt ueber AMSI (Antimalware Scan Interface) den Virenschutz, der auf diesem PC registriert ist –
/// Microsoft Defender, aber auch Avast, ESET, Kaspersky u. a. So nutzt ScanMe dessen komplette Signaturen,
/// auch wenn Defender wegen eines anderen Virenschutzes abgeschaltet ist. Nicht threadsicher.
/// </summary>
public sealed class AmsiScanner : IDisposable
{
    /// <summary>Groessere Dateien werden nicht in den Speicher geladen.</summary>
    public const long MaxFileSize = 32 * 1024 * 1024;

    private const int AMSI_RESULT_DETECTED = 32768;
    private const int AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000;
    private const int AMSI_RESULT_BLOCKED_BY_ADMIN_END = 0x4FFF;

    private IntPtr _context;
    private IntPtr _session;

    /// <summary>Namen der registrierten Virenschutz-Anbieter, z. B. "Microsoft Defender".</summary>
    public IReadOnlyList<string> Providers { get; }

    private AmsiScanner(IntPtr context, IntPtr session, IReadOnlyList<string> providers)
    {
        _context = context;
        _session = session;
        Providers = providers;
    }

    /// <summary>Null, wenn AMSI fehlt oder kein Virenschutz registriert ist – <paramref name="reason"/> sagt warum.</summary>
    public static AmsiScanner? TryOpen(out string? reason)
    {
        var providers = RegisteredProviders();
        if (providers.Count == 0)
        {
            reason = "Kein Virenschutz bei AMSI registriert – keine Prüfung durch den installierten Virenschutz möglich.";
            return null;
        }
        try
        {
            int hr = Native.AmsiInitialize("ScanMe", out var context);
            if (hr != 0) { reason = $"AMSI konnte nicht gestartet werden (0x{hr:X8})."; return null; }
            hr = Native.AmsiOpenSession(context, out var session);
            if (hr != 0)
            {
                Native.AmsiUninitialize(context);
                reason = $"AMSI-Sitzung konnte nicht geöffnet werden (0x{hr:X8}).";
                return null;
            }
            reason = null;
            return new AmsiScanner(context, session, providers);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            reason = "AMSI ist auf diesem Windows nicht verfügbar.";
            return null;
        }
    }

    public AmsiVerdict ScanFile(string path)
    {
        byte[] data;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length == 0 || fi.Length > MaxFileSize) return AmsiVerdict.Skipped;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            data = new byte[fs.Length];
            fs.ReadExactly(data);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return AmsiVerdict.Skipped; }
        return Scan(data, path);
    }

    /// <param name="contentName">Erscheint im Protokoll des Virenschutzes (bei Dateien: der Pfad).</param>
    public AmsiVerdict Scan(byte[] data, string contentName)
    {
        ObjectDisposedException.ThrowIf(_context == IntPtr.Zero, this);
        int hr = Native.AmsiScanBuffer(_context, data, (uint)data.Length, contentName, _session, out int result);
        if (hr != 0) throw new InvalidOperationException($"AMSI-Prüfung fehlgeschlagen (0x{hr:X8}).");
        return Interpret(result);
    }

    public static AmsiVerdict Interpret(int result) => result switch
    {
        >= AMSI_RESULT_DETECTED => AmsiVerdict.Malware,
        >= AMSI_RESULT_BLOCKED_BY_ADMIN_START and <= AMSI_RESULT_BLOCKED_BY_ADMIN_END => AmsiVerdict.BlockedByAdmin,
        _ => AmsiVerdict.Clean,
    };

    /// <summary>Anbieter aus HKLM\SOFTWARE\Microsoft\AMSI\Providers, benannt nach dem Produkt ihrer DLL.</summary>
    public static IReadOnlyList<string> RegisteredProviders()
    {
        var names = new List<string>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\AMSI\Providers");
            foreach (var clsid in key?.GetSubKeyNames() ?? [])
            {
                using var cls = Registry.ClassesRoot.OpenSubKey($@"CLSID\{clsid}");
                using var server = cls?.OpenSubKey("InprocServer32");
                string? dll = (server?.GetValue(null) as string)?.Trim('"');
                string? name = null;
                if (dll != null && dll.Contains(@"\Windows Defender\", StringComparison.OrdinalIgnoreCase)) name = "Microsoft Defender";
                else if (dll != null && File.Exists(dll))
                {
                    try { name = FileVersionInfo.GetVersionInfo(dll).ProductName?.Trim(); } catch { }
                }
                if (string.IsNullOrEmpty(name)) name = (cls?.GetValue(null) as string)?.Trim();
                if (string.IsNullOrEmpty(name)) name = clsid;
                if (!names.Contains(name, StringComparer.OrdinalIgnoreCase)) names.Add(name);
            }
        }
        catch { }
        return names;
    }

    public void Dispose()
    {
        if (_context == IntPtr.Zero) return;
        if (_session != IntPtr.Zero) Native.AmsiCloseSession(_context, _session);
        Native.AmsiUninitialize(_context);
        _session = _context = IntPtr.Zero;
    }

    private static class Native
    {
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        public static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

        [DllImport("amsi.dll")]
        public static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("amsi.dll")]
        public static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);

        [DllImport("amsi.dll")]
        public static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        public static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length, string contentName, IntPtr session, out int result);
    }
}
