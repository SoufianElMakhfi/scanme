using System.IO.MemoryMappedFiles;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace ScanMe.Core.Yara;

/// <summary>
/// YARA-X (VirusTotal) ueber die C-Schnittstelle yara_x_capi.dll. Die DLL und das Regelpaket liegen in Data\yara\
/// neben der EXE (tools/update-yara.ps1). Offiziell gibt es die DLL nur fuer Windows x64 – auf ARM64 ist YARA aus.
/// </summary>
public sealed unsafe class YaraEngine : IDisposable
{
    public static string Dir => Path.Combine(AppContext.BaseDirectory, "Data", "yara");
    public static string DllPath => Path.Combine(Dir, "yara_x_capi.dll");
    public static string PackPath => Path.Combine(Dir, "rules.bin");

    /// <summary>Groessenlimit fuer den Schnellscan (Installer, Spiele-Archive); der vollstaendige Scan prueft alles.</summary>
    public const long QuickMaxFileSize = 64 * 1024 * 1024;

    private readonly object _sync = new();
    private readonly List<string> _matches = new();
    private GCHandle _self;
    private IntPtr _rules, _scanner;

    public RulePack Pack { get; }
    public int RuleCount { get; }

    /// <summary>Warum YARA nicht verfuegbar ist – oder null.</summary>
    public static string? Unavailable =>
        RuntimeInformation.ProcessArchitecture != Architecture.X64 ? "YARA gibt es offiziell nur für Windows x64 – auf diesem Gerät übersprungen."
        : !File.Exists(DllPath) || !File.Exists(PackPath) ? $"YARA-Dateien fehlen ({Dir}) – den Ordner 'Data' neben ScanMe.exe mit entpacken."
        : null;

    private YaraEngine(RulePack pack, int timeoutSeconds)
    {
        Pack = pack;
        IntPtr compiler = IntPtr.Zero;
        try
        {
            Check(Native.yrx_compiler_create(Native.YRX_DISABLE_INCLUDES, out compiler), "Compiler");
            byte[] src = Encoding.UTF8.GetBytes(pack.Source + "\0");
            fixed (byte* p = src) Check(Native.yrx_compiler_add_source(compiler, p), "Regeln");
            _rules = Native.yrx_compiler_build(compiler);
            if (_rules == IntPtr.Zero) throw new InvalidOperationException("YARA-X: Regeln konnten nicht erzeugt werden.");
            RuleCount = Native.yrx_rules_count(_rules);

            Check(Native.yrx_scanner_create(_rules, out _scanner), "Scanner");
            Check(Native.yrx_scanner_set_timeout(_scanner, (ulong)timeoutSeconds), "Timeout");
            _self = GCHandle.Alloc(this);
            Check(Native.yrx_scanner_on_matching_rule(_scanner, &OnMatchingRule, GCHandle.ToIntPtr(_self)), "Callback");
        }
        catch
        {
            Dispose();
            throw;
        }
        finally
        {
            if (compiler != IntPtr.Zero) Native.yrx_compiler_destroy(compiler);
        }
    }

    /// <summary>Entpackt und kompiliert die Regeln (dauert gut eine Sekunde).</summary>
    /// <param name="timeoutSeconds">Schutz gegen Haenger je Datei; bis dahin gefundene Treffer zaehlen trotzdem.</param>
    public static YaraEngine Load(int timeoutSeconds = 10) => new(RulePack.Decode(File.ReadAllBytes(PackPath)), timeoutSeconds);

    /// <summary>Fuer Tests: eigene Regeln statt des Regelpakets.</summary>
    public static YaraEngine FromSource(string source) => new(RulePack.Parse("SCANME-YARA-PACK 1\n---\n" + source), 10);

    /// <summary>Namen der passenden Regeln. Nicht threadsicher genutzt – daher gesperrt.</summary>
    public IReadOnlyList<string> Scan(ReadOnlySpan<byte> data)
    {
        fixed (byte* p = data) return Scan(p, (nuint)data.Length);
    }

    private IReadOnlyList<string> Scan(byte* data, nuint length)
    {
        lock (_sync)
        {
            _matches.Clear();
            int r = Native.yrx_scanner_scan(_scanner, data, length);
            // Zeitueberschreitung: bis dahin gefundene Treffer sind trotzdem gueltig.
            if (r != Native.YRX_SUCCESS && r != Native.YRX_SCAN_TIMEOUT) Check(r, "Scan");
            return _matches.ToList();
        }
    }

    /// <summary>
    /// Prueft eine Datei. Sie wird in den Speicher eingeblendet statt eingelesen: Auch sehr grosse Dateien
    /// (Malware wird gern kuenstlich aufgeblaeht, um Groessenlimits von Scannern zu unterlaufen) brauchen so keinen
    /// ebenso grossen Puffer. Null, wenn die Datei nicht gelesen werden konnte oder groesser als <paramref name="maxSize"/>
    /// ist – das ist kein "nichts gefunden".
    /// </summary>
    public IReadOnlyList<string>? ScanFile(string path, long maxSize = long.MaxValue)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            long length = fs.Length;
            if (length > maxSize) return null;
            if (length == 0) return [];
            using var map = MemoryMappedFile.CreateFromFile(fs, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: false);
            using var view = map.CreateViewAccessor(0, length, MemoryMappedFileAccess.Read);
            byte* p = null;
            view.SafeMemoryMappedViewHandle.AcquirePointer(ref p);
            try { return Scan(p + view.PointerOffset, (nuint)length); }
            finally { view.SafeMemoryMappedViewHandle.ReleasePointer(); }
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnMatchingRule(IntPtr rule, IntPtr userData)
    {
        if (GCHandle.FromIntPtr(userData).Target is not YaraEngine self) return;
        if (Native.yrx_rule_identifier(rule, out byte* ident, out nuint len) == Native.YRX_SUCCESS)
            self._matches.Add(Encoding.UTF8.GetString(ident, (int)len));
    }

    private static void Check(int result, string what)
    {
        if (result == Native.YRX_SUCCESS) return;
        string? detail = Marshal.PtrToStringUTF8(Native.yrx_last_error());
        throw new InvalidOperationException($"YARA-X ({what}): Fehler {result}{(detail != null ? " – " + detail : "")}");
    }

    public void Dispose()
    {
        if (_scanner != IntPtr.Zero) { Native.yrx_scanner_destroy(_scanner); _scanner = IntPtr.Zero; }
        if (_rules != IntPtr.Zero) { Native.yrx_rules_destroy(_rules); _rules = IntPtr.Zero; }
        if (_self.IsAllocated) _self.Free();
    }

    /// <summary>Auszug aus yara_x.h (YARA-X C-API).</summary>
    private static class Native
    {
        private const string Lib = "yara_x_capi";
        public const int YRX_SUCCESS = 0;
        public const int YRX_SCAN_TIMEOUT = 4;
        public const uint YRX_DISABLE_INCLUDES = 32;

        // Die DLL liegt nicht im EXE-Ordner, sondern in Data\yara\.
        static Native() => NativeLibrary.SetDllImportResolver(typeof(Native).Assembly,
            (name, _, _) => name == Lib && NativeLibrary.TryLoad(DllPath, out var h) ? h : IntPtr.Zero);

        [DllImport(Lib)] public static extern IntPtr yrx_last_error();
        [DllImport(Lib)] public static extern int yrx_compiler_create(uint flags, out IntPtr compiler);
        [DllImport(Lib)] public static extern void yrx_compiler_destroy(IntPtr compiler);
        [DllImport(Lib)] public static extern int yrx_compiler_add_source(IntPtr compiler, byte* src);
        [DllImport(Lib)] public static extern IntPtr yrx_compiler_build(IntPtr compiler);
        [DllImport(Lib)] public static extern int yrx_rules_count(IntPtr rules);
        [DllImport(Lib)] public static extern void yrx_rules_destroy(IntPtr rules);
        [DllImport(Lib)] public static extern int yrx_scanner_create(IntPtr rules, out IntPtr scanner);
        [DllImport(Lib)] public static extern void yrx_scanner_destroy(IntPtr scanner);
        [DllImport(Lib)] public static extern int yrx_scanner_set_timeout(IntPtr scanner, ulong seconds);
        [DllImport(Lib)] public static extern int yrx_scanner_on_matching_rule(IntPtr scanner, delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void> callback, IntPtr userData);
        [DllImport(Lib)] public static extern int yrx_scanner_scan(IntPtr scanner, byte* data, nuint len);
        [DllImport(Lib)] public static extern int yrx_rule_identifier(IntPtr rule, out byte* ident, out nuint len);
    }
}
