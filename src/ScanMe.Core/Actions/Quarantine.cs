using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using ScanMe.Core.Inventory;
using ScanMe.Core.Trust;

namespace ScanMe.Core.Actions;

public sealed class QuarantineItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string OriginalPath { get; set; } = "";
    public string? Sha256 { get; set; }
    public long Size { get; set; }
    public DateTime QuarantinedAt { get; set; } = DateTime.Now;
    public string? Reason { get; set; }
    public FileAttributes Attributes { get; set; }

    /// <summary>Datei war gesperrt (z. B. geladener Treiber) und wird beim naechsten Neustart entfernt.</summary>
    public bool PendingReboot { get; set; }
}

/// <summary>
/// Quarantaene: Dateien werden XOR-kodiert (nicht mehr ausfuehrbar, Virenscanner schlagen nicht erneut an)
/// in einen geschuetzten Ordner verschoben und koennen jederzeit wiederhergestellt werden.
/// </summary>
public static class Quarantine
{
    private const byte Key = 0xA7;
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, int dwFlags);
    private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

    public static IReadOnlyList<QuarantineItem> List()
    {
        var items = new List<QuarantineItem>();
        foreach (var dir in Directory.GetDirectories(AppPaths.QuarantineDir))
        {
            try
            {
                var item = JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllText(Path.Combine(dir, "manifest.json")));
                if (item != null) items.Add(item);
            }
            catch { }
        }
        return items.OrderByDescending(i => i.QuarantinedAt).ToList();
    }

    public static ActionResult Add(string path, string? reason)
    {
        string? block = SafetyGuard.CheckFile(path);
        if (block != null) return ActionResult.Fail(block);

        var item = new QuarantineItem
        {
            OriginalPath = path,
            Sha256 = FileTrustService.TryHash(path),
            Size = new FileInfo(path).Length,
            Reason = reason,
            Attributes = File.GetAttributes(path),
        };
        string dir = Path.Combine(AppPaths.QuarantineDir, item.Id);
        Directory.CreateDirectory(dir);

        // Laufende Prozesse dieser Datei beenden (nur wenn erlaubt)
        KillProcessesUsing(path);

        try
        {
            Encode(path, Path.Combine(dir, "data.bin"));
        }
        catch (Exception ex)
        {
            Directory.Delete(dir, true);
            return ActionResult.Fail("Datei konnte nicht gelesen werden: " + ex.Message);
        }

        try
        {
            File.SetAttributes(path, FileAttributes.Normal);
            File.Delete(path);
        }
        catch
        {
            // Gesperrt (z. B. geladener Treiber) -> beim naechsten Neustart loeschen
            if (!MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT))
            {
                Directory.Delete(dir, true);
                return ActionResult.Fail("Datei ist gesperrt und konnte nicht zum Loeschen vorgemerkt werden.");
            }
            item.PendingReboot = true;
        }

        File.WriteAllText(Path.Combine(dir, "manifest.json"), JsonSerializer.Serialize(item, Json));
        FileTrustService.Shared.Invalidate(path);
        return ActionResult.Ok(item.PendingReboot
            ? "Datei gesichert; sie ist gerade in Benutzung und wird beim naechsten Neustart entfernt."
            : "Datei in Quarantaene verschoben. Wiederherstellung jederzeit moeglich.");
    }

    public static ActionResult Restore(string id)
    {
        string dir = Path.Combine(AppPaths.QuarantineDir, id);
        var item = JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllText(Path.Combine(dir, "manifest.json")))!;
        if (File.Exists(item.OriginalPath))
        {
            if (!item.PendingReboot) return ActionResult.Fail("Am Originalort existiert bereits eine Datei.");
            // Datei ist noch da (war gesperrt) – nur die vorgemerkte Loeschung stornieren.
            CancelPendingDelete(item.OriginalPath);
            Directory.Delete(dir, true);
            return ActionResult.Ok($"Vorgemerkte Loeschung storniert: {item.OriginalPath}");
        }
        Directory.CreateDirectory(Path.GetDirectoryName(item.OriginalPath)!);
        Encode(Path.Combine(dir, "data.bin"), item.OriginalPath); // XOR ist symmetrisch
        try { File.SetAttributes(item.OriginalPath, item.Attributes); } catch { }
        Directory.Delete(dir, true);
        return ActionResult.Ok($"Wiederhergestellt: {item.OriginalPath}");
    }

    public static ActionResult Delete(string id)
    {
        Directory.Delete(Path.Combine(AppPaths.QuarantineDir, id), true);
        return ActionResult.Ok("Endgueltig geloescht.");
    }

    /// <summary>Entfernt "Loeschen beim Neustart" fuer eine Datei aus PendingFileRenameOperations (Paare: Quelle, Ziel; Ziel leer = loeschen).</summary>
    private static void CancelPendingDelete(string path)
    {
        const string key = @"SYSTEM\CurrentControlSet\Control\Session Manager";
        using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(key, writable: true);
        if (k?.GetValue("PendingFileRenameOperations") is not string[] ops) return;
        var kept = new List<string>();
        for (int i = 0; i + 1 < ops.Length; i += 2)
        {
            string src = ops[i].StartsWith(@"\??\", StringComparison.Ordinal) ? ops[i][4..] : ops[i];
            if (src.Equals(path, StringComparison.OrdinalIgnoreCase) && ops[i + 1].Length == 0) continue;
            kept.Add(ops[i]);
            kept.Add(ops[i + 1]);
        }
        if (kept.Count == 0) k.DeleteValue("PendingFileRenameOperations", false);
        else k.SetValue("PendingFileRenameOperations", kept.ToArray(), Microsoft.Win32.RegistryValueKind.MultiString);
    }

    private static void Encode(string src, string dst)
    {
        using var input = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var output = new FileStream(dst, FileMode.Create, FileAccess.Write);
        var buf = new byte[1 << 16];
        int n;
        while ((n = input.Read(buf, 0, buf.Length)) > 0)
        {
            for (int i = 0; i < n; i++) buf[i] ^= Key;
            output.Write(buf, 0, n);
        }
    }

    private static void KillProcessesUsing(string path)
    {
        var snap = ProcessSnapshot.Capture(measureCpu: false, crossView: false);
        foreach (var p in snap.Processes.Values.Where(p => string.Equals(p.ImagePath, path, StringComparison.OrdinalIgnoreCase)))
        {
            if (SafetyGuard.CheckProcess(p.Pid) != null) continue;
            try
            {
                using var proc = Process.GetProcessById(p.Pid);
                proc.Kill();
                proc.WaitForExit(3000);
            }
            catch { }
        }
    }
}
