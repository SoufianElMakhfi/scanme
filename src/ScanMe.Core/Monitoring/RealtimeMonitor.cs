using System.Collections.Concurrent;
using System.Management;
using ScanMe.Core.Engine;
using ScanMe.Core.Inventory;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Models;
using ScanMe.Core.Trust;
using ScanMe.Core.Util;

namespace ScanMe.Core.Monitoring;

public enum MonitorKind { Process, Autostart, File, Network, System }

public sealed record MonitorEvent(DateTime Time, MonitorKind Kind, Finding Finding);

/// <summary>
/// Echtzeitueberwachung: neue Prozesse, neue Autostarts, neue ausfuehrbare Dateien/Phishing-Anhaenge,
/// neue Netzwerkverbindungen unsignierter Programme und Aenderungen der Hosts-Datei.
/// Jedes Ereignis wird sofort mit denselben Regeln wie der Scan bewertet.
/// </summary>
public sealed class RealtimeMonitor : IDisposable
{
    private readonly FileTrustService _trust = FileTrustService.Shared;
    private readonly List<IDisposable> _resources = new();
    private ManagementEventWatcher? _processWatcher;
    private CancellationTokenSource? _cts;
    private readonly ConcurrentDictionary<string, DateTime> _recentFiles = new(StringComparer.OrdinalIgnoreCase);

    public event Action<MonitorEvent>? Detected;
    public event Action<string>? StatusChanged;

    public bool IsRunning { get; private set; }

    public void Start()
    {
        if (IsRunning) return;
        IsRunning = true;
        _cts = new CancellationTokenSource();
        StartProcessWatcher();
        StartFileWatchers();
        _ = Task.Run(() => PollAutostartsAsync(_cts.Token));
        _ = Task.Run(() => PollNetworkAsync(_cts.Token));
        StatusChanged?.Invoke("Überwachung aktiv");
    }

    public void Stop()
    {
        if (!IsRunning) return;
        IsRunning = false;
        _cts?.Cancel();
        try { _processWatcher?.Stop(); } catch { }
        _processWatcher?.Dispose();
        _processWatcher = null;
        foreach (var r in _resources) r.Dispose();
        _resources.Clear();
        StatusChanged?.Invoke("Überwachung gestoppt");
    }

    public void Dispose() => Stop();

    private void Raise(MonitorKind kind, Finding f)
    {
        RiskScorer.Finalize(f);
        PlainLanguage.Apply(f);
        try { Detected?.Invoke(new MonitorEvent(DateTime.Now, kind, f)); } catch { }
    }

    // ------------------------------------------------------------------
    // Prozesse
    // ------------------------------------------------------------------

    private void StartProcessWatcher()
    {
        try
        {
            // Mit Adminrechten: sofortige Kernel-Benachrichtigung; sonst WMI-Abfrage im Sekundentakt.
            var query = SystemEnv.IsElevated
                ? new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace")
                : new WqlEventQuery("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
            _processWatcher = new ManagementEventWatcher(query);
            _processWatcher.EventArrived += (_, e) =>
            {
                try
                {
                    int pid, ppid;
                    string name;
                    string? cmd = null;
                    if (e.NewEvent["TargetInstance"] is ManagementBaseObject ti)
                    {
                        pid = Convert.ToInt32(ti["ProcessId"]);
                        ppid = Convert.ToInt32(ti["ParentProcessId"]);
                        name = ti["Name"]?.ToString() ?? "?";
                        cmd = ti["CommandLine"]?.ToString();
                    }
                    else
                    {
                        pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
                        ppid = Convert.ToInt32(e.NewEvent["ParentProcessID"]);
                        name = e.NewEvent["ProcessName"]?.ToString() ?? "?";
                    }
                    Task.Run(() => OnProcessStarted(pid, ppid, name, cmd));
                }
                catch { }
            };
            _processWatcher.Start();
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke("Prozessüberwachung nicht verfügbar: " + ex.Message);
        }
    }

    private static readonly HashSet<string> DocumentApps = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "acrord32.exe", "acrobat.exe", "olk.exe", "thunderbird.exe",
    };

    private void OnProcessStarted(int pid, int ppid, string name, string? cmd)
    {
        string? path = ProcessSnapshot.QueryImagePath(pid);
        if (cmd == null)
        {
            try
            {
                using var s = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject mo in s.Get()) using (mo) cmd = mo["CommandLine"]?.ToString();
            }
            catch { }
        }
        string? parentPath = ProcessSnapshot.QueryImagePath(ppid);
        string parentName = parentPath != null ? Path.GetFileName(parentPath) : $"PID {ppid}";

        var f = new Finding
        {
            ScannerId = "monitor",
            Category = FindingCategory.Process,
            Title = $"Prozess gestartet: {name}",
            ProcessId = pid,
            Description = $"{name} (PID {pid}) wurde von {parentName} gestartet.",
        };
        f.Detail("Kommandozeile", cmd).Detail("Elternprozess", parentPath ?? parentName);

        if (path != null) ExecutableAssessor.Assess(f, path, _trust);
        foreach (var rule in CommandLineRules.Match(cmd))
            f.AddIndicator("CMD_" + rule.Id, rule.Text + (rule.Mitre != null ? $" [{rule.Mitre}]" : ""), rule.Weight);
        if (DocumentApps.Contains(parentName) && ExecutableAssessor.LolBins.Contains(name))
            f.AddIndicator("DOC_SPAWN", $"{parentName} hat {name} gestartet – typisch für bösartige Makros/Phishing-Anhänge", 65);

        f.Explanation = "Jeder neue Prozess wird sofort mit denselben Regeln wie beim Scan bewertet.";
        f.Recommendation = "Bei hoher Bewertung: Prozess beenden und die Datei in Quarantäne verschieben.";
        if (!f.IsProtected)
            f.Actions.Insert(0, new RemediationAction { Kind = RemediationKind.KillProcess, Label = "Prozess beenden", Target = pid.ToString() });
        Raise(MonitorKind.Process, f);
    }

    // ------------------------------------------------------------------
    // Dateien
    // ------------------------------------------------------------------

    private static readonly HashSet<string> WatchedExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".pif", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
        ".lnk", ".iso", ".img", ".vhd", ".vhdx", ".one", ".docm", ".xlsm", ".sys",
    };

    private void StartFileWatchers()
    {
        var dirs = new List<(string Dir, bool Recursive)>();
        foreach (var p in SystemEnv.UserProfiles())
        {
            dirs.Add((Path.Combine(p, "Downloads"), true));
            dirs.Add((Path.Combine(p, "Desktop"), false));
            dirs.Add((Path.Combine(p, @"AppData\Local\Temp"), true));
            dirs.Add((Path.Combine(p, @"AppData\Roaming"), true));
            dirs.Add((Path.Combine(p, @"AppData\Local\Microsoft\Windows"), true));
            dirs.Add((Path.Combine(p, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"), false));
        }
        dirs.Add((Path.Combine(PathUtil.ProgramData, @"Microsoft\Windows\Start Menu\Programs\StartUp"), false));
        dirs.Add((Path.Combine(PathUtil.UsersRoot, "Public"), true));
        dirs.Add((Path.Combine(PathUtil.WindowsDir, "Temp"), true));

        foreach (var (dir, recursive) in dirs.Where(d => Directory.Exists(d.Dir)))
        {
            try
            {
                var w = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = recursive,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                    InternalBufferSize = 64 * 1024,
                };
                w.Created += (_, e) => OnFileEvent(e.FullPath);
                w.Renamed += (_, e) => OnFileEvent(e.FullPath);
                w.EnableRaisingEvents = true;
                _resources.Add(w);
            }
            catch { }
        }

        // Hosts-Datei
        try
        {
            string etc = Path.Combine(PathUtil.System32, @"drivers\etc");
            var hw = new FileSystemWatcher(etc, "hosts") { NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size };
            hw.Changed += (_, _) => OnHostsChanged();
            hw.EnableRaisingEvents = true;
            _resources.Add(hw);
        }
        catch { }
    }

    private void OnFileEvent(string path)
    {
        if (!WatchedExt.Contains(Path.GetExtension(path))) return;
        // Browser-Downloads entstehen als .crdownload/.tmp und werden umbenannt – Ereignisse entprellen
        if (_recentFiles.TryGetValue(path, out var last) && (DateTime.Now - last).TotalSeconds < 10) return;
        _recentFiles[path] = DateTime.Now;
        Task.Run(async () =>
        {
            await Task.Delay(2500); // Schreibvorgang abwarten
            if (!File.Exists(path)) return;
            var loc = LocationClassifier.Classify(path);
            string ext = Path.GetExtension(path).ToLowerInvariant();
            var f = new Finding
            {
                ScannerId = "monitor",
                Category = FindingCategory.FileSystem,
                Title = $"Neue Datei: {Path.GetFileName(path)}",
                FilePath = path,
                Location = Path.GetDirectoryName(path),
            };
            ExecutableAssessor.Assess(f, path, _trust);
            if (path.Contains(@"\Start Menu\Programs\Startup", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\Start Menu\Programs\StartUp", StringComparison.OrdinalIgnoreCase))
                f.AddIndicator("NEW_STARTUP", "Datei wurde im Autostart-Ordner angelegt", 40);
            // In Temp schreiben viele Apps .js-Dateien; relevant sind dort nur aus Archiven entpackte Dateien
            // (Doppelklick auf Anhang in ZIP/RAR = klassische Phishing-Kette) oder solche mit Internet-Markierung.
            bool fromArchive = path.Contains(@"\Temp1_", StringComparison.OrdinalIgnoreCase) || path.Contains(@".zip\", StringComparison.OrdinalIgnoreCase)
                               || path.Contains(@"\Rar$", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\7z", StringComparison.OrdinalIgnoreCase);
            bool phishingType = ext is ".iso" or ".img" or ".vhd" or ".vhdx" or ".hta" or ".js" or ".jse" or ".vbs" or ".vbe" or ".wsf" or ".one";
            if (phishingType && new FileInfo(path).Length < 2 * 1024 * 1024
                && (loc == LocationKind.Downloads || (loc == LocationKind.Temp && (fromArchive || ZoneIdentifier.Read(path).ZoneId >= 3))))
                f.AddIndicator("PHISHING_TYPE", fromArchive
                    ? $"{ext}-Datei aus einem Archiv geöffnet – klassischer Weg von Phishing-Anhängen"
                    : $"{ext}-Datei heruntergeladen – typisches Format für Phishing-Anhänge", 35);
            if (ext == ".lnk" && loc is LocationKind.Downloads or LocationKind.Temp)
            {
                var (target, args) = ShortcutReader.Read(path);
                if (target != null && ExecutableAssessor.LolBins.Contains(Path.GetFileName(target)) && !string.IsNullOrWhiteSpace(args))
                    f.AddIndicator("LNK_LOLBIN", $"Verknüpfung startet {Path.GetFileName(target)} mit Parametern (LNK-Phishing)", 55);
            }
            if (ext == ".sys")
                f.AddIndicator("NEW_DRIVER", "Neue Treiberdatei außerhalb des Windows-Verzeichnisses", 30);

            if (f.Indicators.Sum(i => i.Weight) < 15) return;
            f.Description = $"Neue Datei {path}" + (f.Details.TryGetValue("Download-Quelle", out var url) ? $", heruntergeladen von {url}" : "") + ".";
            f.Explanation = "Neue Programme, Skripte und typische Phishing-Formate an diesen Orten werden sofort geprüft.";
            f.Recommendation = "Wenn Sie die Datei nicht bewusst heruntergeladen haben: nicht öffnen und in Quarantäne verschieben.";
            Raise(MonitorKind.File, f);
        });
    }

    private void OnHostsChanged()
    {
        if (_recentFiles.TryGetValue("hosts", out var last) && (DateTime.Now - last).TotalSeconds < 10) return;
        _recentFiles["hosts"] = DateTime.Now;
        var f = new Finding
        {
            ScannerId = "monitor",
            Category = FindingCategory.Network,
            Title = "Hosts-Datei wurde geändert",
            FilePath = Path.Combine(PathUtil.System32, @"drivers\etc\hosts"),
            Description = "Die Hosts-Datei wurde soeben verändert.",
            Explanation = "Malware ändert die Hosts-Datei, um Webseiten (z. B. Banken) auf Phishing-Server umzuleiten oder Sicherheitsupdates zu blockieren.",
            Recommendation = "Wenn Sie die Änderung nicht selbst vorgenommen haben: vollständigen Scan starten.",
        };
        f.AddIndicator("HOSTS_CHANGED", "Hosts-Datei geändert", 40);
        Raise(MonitorKind.System, f);
    }

    // ------------------------------------------------------------------
    // Autostarts (Polling, da Registry-Ueberwachung pro Schluessel aufwendig ist)
    // ------------------------------------------------------------------

    private static Dictionary<string, string> SnapshotAutostarts()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var keys = new List<string>
        {
            @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            @"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        };
        foreach (var h in RegistryUtil.LoadedUserHives())
        {
            keys.Add($@"{h}\Software\Microsoft\Windows\CurrentVersion\Run");
            keys.Add($@"{h}\Software\Microsoft\Windows\CurrentVersion\RunOnce");
        }
        foreach (var k in keys)
            foreach (var (name, value) in RegistryUtil.Values(k))
            {
                if (k.EndsWith("Winlogon") && name is not ("Shell" or "Userinit")) continue;
                map[$"Registry|{k}|{name}"] = value?.ToString() ?? "";
            }

        const string services = @"HKLM\SYSTEM\CurrentControlSet\Services";
        foreach (var svc in RegistryUtil.SubKeys(services))
        {
            string? image = RegistryUtil.GetString($@"{services}\{svc}", "ImagePath");
            if (image != null) map[$"Dienst|{svc}"] = image;
        }

        try
        {
            string tasks = Path.Combine(PathUtil.System32, "Tasks");
            foreach (var t in Directory.EnumerateFiles(tasks, "*", new System.IO.EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
                map[$"Task|{t[tasks.Length..]}"] = t;
        }
        catch { }
        return map;
    }

    private async Task PollAutostartsAsync(CancellationToken ct)
    {
        var known = SnapshotAutostarts();
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(TimeSpan.FromSeconds(20), ct); } catch { return; }
            Dictionary<string, string> now;
            try { now = SnapshotAutostarts(); } catch { continue; }
            foreach (var (key, value) in now)
            {
                if (known.TryGetValue(key, out var old) && old == value) continue;
                var parts = key.Split('|');
                string type = parts[0];
                string command = type == "Task" ? TaskCommand(value) ?? value : value;
                var f = new Finding
                {
                    ScannerId = "monitor",
                    Category = FindingCategory.Persistence,
                    Title = $"Neuer Autostart ({type}): {parts[^1].TrimStart('\\')}",
                    Location = type == "Registry" ? parts[1] : parts[^1],
                    Description = $"Neu eingetragen: {command}",
                    Explanation = "Malware trägt sich unmittelbar nach der Infektion in den Autostart ein. Neue Einträge werden deshalb sofort gemeldet.",
                    Recommendation = "Haben Sie gerade ein Programm installiert? Falls nicht, Eintrag prüfen und ggf. entfernen (vollständigen Scan starten).",
                };
                f.AddIndicator("NEW_AUTOSTART", "Neuer Autostart-Eintrag", 20);
                var (exe, payload) = PathUtil.ResolveCommandLine(command);
                if ((payload ?? exe) is { } target) ExecutableAssessor.Assess(f, target, _trust);
                foreach (var rule in CommandLineRules.Match(command))
                    f.AddIndicator("CMD_" + rule.Id, rule.Text, rule.Weight);
                Raise(MonitorKind.Autostart, f);
            }
            known = now;
        }
    }

    private static string? TaskCommand(string xmlPath)
    {
        try
        {
            var doc = System.Xml.Linq.XDocument.Load(xmlPath);
            var exec = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Exec");
            if (exec == null) return null;
            string? cmd = exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Command")?.Value;
            string? args = exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Arguments")?.Value;
            return $"\"{cmd}\" {args}".Trim();
        }
        catch { return null; }
    }

    // ------------------------------------------------------------------
    // Netzwerk
    // ------------------------------------------------------------------

    private async Task PollNetworkAsync(CancellationToken ct)
    {
        var seen = new HashSet<string>();
        foreach (var c in ConnectionTable.Capture()) seen.Add($"{c.Pid}|{c.RemoteAddress}|{c.RemotePort}|{c.LocalPort}|{c.State}");

        int[] badPorts = [4444, 1337, 31337, 6666, 6667, 9001, 9050, 1604, 5552, 3333, 14444];
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(TimeSpan.FromSeconds(8), ct); } catch { return; }
            List<Connection> conns;
            try { conns = ConnectionTable.Capture(); } catch { continue; }
            foreach (var c in conns)
            {
                string key = $"{c.Pid}|{c.RemoteAddress}|{c.RemotePort}|{c.LocalPort}|{c.State}";
                if (!seen.Add(key)) continue;
                bool listening = c.Protocol == Protocol.Tcp && c.State == "LISTEN";
                if (!(c.IsEstablished && c.IsExternal) && !listening) continue;

                string? path = ProcessSnapshot.QueryImagePath(c.Pid);
                if (path == null) continue;
                var info = _trust.Get(path);
                bool lolbin = info.IsWindowsComponent && ExecutableAssessor.LolBins.Contains(Path.GetFileName(path));
                bool badPort = badPorts.Contains(c.RemotePort) || (listening && badPorts.Contains(c.LocalPort));
                if (info.Signature == SignatureState.Valid && !lolbin && !badPort) continue;

                var f = new Finding
                {
                    ScannerId = "monitor",
                    Category = FindingCategory.Network,
                    Title = listening ? $"Neuer offener Port: {Path.GetFileName(path)} :{c.LocalPort}" : $"Neue Verbindung: {Path.GetFileName(path)} → {c.RemoteAddress}:{c.RemotePort}",
                    ProcessId = c.Pid,
                    Description = listening ? $"{path} wartet auf Port {c.LocalPort} auf eingehende Verbindungen."
                                            : $"{path} hat eine Verbindung zu {c.RemoteAddress}:{c.RemotePort} aufgebaut.",
                    Explanation = "Unsignierte Programme oder Skript-Hosts mit Internetverbindung können Schadsoftware sein, die Befehle empfängt oder Daten ausleitet.",
                    Recommendation = "Programm prüfen; bei Unbekanntem Prozess beenden.",
                };
                ExecutableAssessor.Assess(f, path, _trust);
                if (lolbin) f.AddIndicator("NET_LOLBIN", $"{Path.GetFileName(path)} kommuniziert mit dem Internet", 40);
                if (badPort) f.AddIndicator("NET_BADPORT", "Typischer Port von Hacking-Tools/RATs/Minern", 35);
                if (!f.IsProtected)
                    f.Actions.Insert(0, new RemediationAction { Kind = RemediationKind.KillProcess, Label = "Prozess beenden", Target = c.Pid.ToString() });
                Raise(MonitorKind.Network, f);
            }
            if (seen.Count > 50_000) seen.Clear();
        }
    }
}
