using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using ScanMe.Core.Native;

namespace ScanMe.Core.Inventory;

public sealed class ProcessEntry
{
    public int Pid { get; init; }
    public int ParentPid { get; init; }
    public string Name { get; init; } = "";
    public string? ImagePath { get; set; }
    public string? CommandLine { get; set; }
    public int SessionId { get; init; }
    public DateTime? StartTime { get; init; }
    public int Threads { get; init; }
    public long WorkingSet { get; init; }
    public long PrivateBytes { get; init; }
    public long CpuTime100ns { get; init; }
    public double CpuPercent { get; set; }
    public bool HasVisibleWindow { get; set; }

    /// <summary>Von welchen Erfassungsmethoden der Prozess gesehen wurde.</summary>
    public HashSet<string> SeenBy { get; } = new();

    public bool IsService => SessionId == 0;
}

/// <summary>
/// Momentaufnahme aller Prozesse. Kombiniert mehrere Quellen (Kernel-Liste, PSAPI, WMI,
/// PID-Bruteforce), um Prozesse aufzudecken, die vor einzelnen Sichten versteckt werden.
/// </summary>
public sealed class ProcessSnapshot
{
    public const string SrcKernel = "NtQuerySystemInformation";
    public const string SrcPsapi = "EnumProcesses";
    public const string SrcWmi = "WMI";
    public const string SrcBrute = "PID-Bruteforce";

    private const uint STILL_ACTIVE = 259;

    public Dictionary<int, ProcessEntry> Processes { get; } = new();
    public DateTime TakenAt { get; } = DateTime.Now;

    /// <summary>PIDs, die nur ueber Bruteforce gefunden wurden (moeglicherweise versteckt).</summary>
    public List<(int Pid, string? Path)> HiddenCandidates { get; } = new();

    public ProcessEntry? Get(int pid) => Processes.TryGetValue(pid, out var p) ? p : null;

    public static ProcessSnapshot Capture(bool measureCpu = true, bool crossView = true)
    {
        var snap = new ProcessSnapshot();

        var first = QueryKernel();
        DateTime t0 = DateTime.UtcNow;
        Dictionary<int, long>? cpuBefore = null;
        if (measureCpu)
        {
            cpuBefore = first.ToDictionary(p => p.Pid, p => p.CpuTime100ns);
            Thread.Sleep(1000);
            first = QueryKernel();
        }
        double elapsed100ns = (DateTime.UtcNow - t0).Ticks;

        foreach (var p in first)
        {
            if (cpuBefore != null && cpuBefore.TryGetValue(p.Pid, out var before) && elapsed100ns > 0)
                p.CpuPercent = Math.Max(0, (p.CpuTime100ns - before) / elapsed100ns / Environment.ProcessorCount * 100.0);
            p.SeenBy.Add(SrcKernel);
            p.ImagePath = QueryImagePath(p.Pid);
            snap.Processes[p.Pid] = p;
        }

        // --- WMI: Kommandozeilen + zweite Sicht ---
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId, CommandLine, ExecutablePath FROM Win32_Process");
            searcher.Options.Timeout = TimeSpan.FromSeconds(30);
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    int pid = Convert.ToInt32(mo["ProcessId"]);
                    if (snap.Processes.TryGetValue(pid, out var entry))
                    {
                        entry.SeenBy.Add(SrcWmi);
                        entry.CommandLine = mo["CommandLine"] as string;
                        entry.ImagePath ??= mo["ExecutablePath"] as string;
                    }
                }
            }
        }
        catch { /* WMI-Dienst defekt -> eigener Fund im Konfigurationsscanner */ }

        // --- Fenster ---
        var withWindow = new HashSet<int>();
        NativeMethods.EnumWindows((h, _) =>
        {
            if (NativeMethods.IsWindowVisible(h))
            {
                NativeMethods.GetWindowThreadProcessId(h, out int wpid);
                withWindow.Add(wpid);
            }
            return true;
        }, IntPtr.Zero);
        foreach (var p in snap.Processes.Values) p.HasVisibleWindow = withWindow.Contains(p.Pid);

        if (crossView)
        {
            // --- PSAPI ---
            var ids = new int[16384];
            if (NativeMethods.EnumProcesses(ids, ids.Length * 4, out int needed))
                foreach (var pid in ids.Take(needed / 4))
                    if (snap.Processes.TryGetValue(pid, out var e)) e.SeenBy.Add(SrcPsapi);

            // --- Bruteforce: jede PID direkt oeffnen ---
            int maxPid = Math.Max(65536, snap.Processes.Keys.DefaultIfEmpty(0).Max() + 40000);
            var candidates = new List<int>();
            for (int pid = 8; pid <= maxPid; pid += 4)
            {
                if (snap.Processes.ContainsKey(pid)) continue;
                if (IsAlive(pid)) candidates.Add(pid);
            }

            if (candidates.Count > 0)
            {
                // Gegenpruefung gegen eine neue Kernel-Liste (Prozess koennte inzwischen gestartet sein).
                var recheck = QueryKernel().Select(p => p.Pid).ToHashSet();
                foreach (var pid in candidates)
                    if (!recheck.Contains(pid) && IsAlive(pid))
                        snap.HiddenCandidates.Add((pid, QueryImagePath(pid)));
            }
        }

        return snap;
    }

    private static bool IsAlive(int pid)
    {
        IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero)
        {
            // Zugriff verweigert heisst: PID existiert. Ungueltiger Parameter heisst: existiert nicht.
            // Geschuetzte Prozesse ohne Zugriff koennen wir nicht auf "beendet" pruefen und ignorieren sie.
            return false;
        }
        try
        {
            return NativeMethods.GetExitCodeProcess(h, out uint code) && code == STILL_ACTIVE;
        }
        finally { NativeMethods.CloseHandle(h); }
    }

    public static string? QueryImagePath(int pid)
    {
        IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            uint size = (uint)sb.Capacity;
            return NativeMethods.QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
        }
        finally { NativeMethods.CloseHandle(h); }
    }

    private static List<ProcessEntry> QueryKernel()
    {
        int size = 1 << 20;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            while (true)
            {
                buffer = Marshal.AllocHGlobal(size);
                uint status = NativeMethods.NtQuerySystemInformation(NativeMethods.SystemProcessInformation, buffer, size, out int needed);
                if (status == NativeMethods.STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                    size = Math.Max(size * 2, needed + 65536);
                    continue;
                }
                if (status != 0) return new List<ProcessEntry>();
                break;
            }

            var list = new List<ProcessEntry>();
            IntPtr cur = buffer;
            while (true)
            {
                var spi = Marshal.PtrToStructure<NativeMethods.SYSTEM_PROCESS_INFORMATION>(cur);
                int pid = (int)spi.UniqueProcessId;
                string name = spi.ImageName.Buffer != IntPtr.Zero
                    ? Marshal.PtrToStringUni(spi.ImageName.Buffer, spi.ImageName.Length / 2)
                    : pid == 0 ? "System Idle Process" : "System";

                list.Add(new ProcessEntry
                {
                    Pid = pid,
                    ParentPid = (int)spi.InheritedFromUniqueProcessId,
                    Name = name,
                    SessionId = (int)spi.SessionId,
                    StartTime = spi.CreateTime > 0 ? DateTime.FromFileTime(spi.CreateTime) : null,
                    Threads = (int)spi.NumberOfThreads,
                    WorkingSet = (long)(ulong)spi.WorkingSetSize,
                    PrivateBytes = (long)(ulong)spi.PrivatePageCount,
                    CpuTime100ns = spi.KernelTime + spi.UserTime,
                });

                if (spi.NextEntryOffset == 0) break;
                cur += (int)spi.NextEntryOffset;
            }
            return list;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
    }
}
