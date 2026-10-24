using System.Management;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using ScanMe.Core.Actions;
using ScanMe.Core.Util;

namespace ScanMe.Core.Baseline;

/// <summary>Ein gespeicherter "bekannt guter" Zustand: Kategorie -> (Schluessel -> Wert).</summary>
public sealed class BaselineSnapshot
{
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public string MachineName { get; set; } = Environment.MachineName;
    public string OsVersion { get; set; } = SystemEnv.OsDescription;
    public Dictionary<string, Dictionary<string, string>> Categories { get; set; } = new();

    /// <summary>Pruefsumme ueber den Inhalt – zeigt nachtraegliche Aenderungen an der Datei an.</summary>
    public string? Checksum { get; set; }
}

public enum ChangeKind { Added, Removed, Changed }

public sealed record BaselineChange(string Category, string Key, ChangeKind Kind, string? Before, string? After);

/// <summary>
/// Baseline-Vergleich wie in professionellen Umgebungen: Statt jede Datei zu bewerten, wird gemeldet,
/// was sich seit einem bekannt sauberen Zustand veraendert hat (neue Autostarts, Dienste, Treiber, Admins ...).
/// </summary>
public static class BaselineService
{
    public static string FilePath => Path.Combine(AppPaths.DataDir, "baseline.json");
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public const string CatAutostart = "Autostart";
    public const string CatService = "Dienst";
    public const string CatDriver = "Treiber";
    public const string CatTask = "Geplante Aufgabe";
    public const string CatExclusion = "Defender-Ausnahme";
    public const string CatAdmin = "Administrator";
    public const string CatAccount = "Benutzerkonto";
    public const string CatSoftware = "Programm";
    public const string CatRootCert = "Stammzertifikat";
    public const string CatWmi = "WMI-Abonnement";
    public const string CatHosts = "Hosts-Datei";
    public const string CatBrowserExt = "Browser-Erweiterung";

    // ------------------------------------------------------------------

    public static BaselineSnapshot Capture()
    {
        var s = new BaselineSnapshot();
        void Put(string cat, string key, string? value)
        {
            if (!s.Categories.TryGetValue(cat, out var d)) s.Categories[cat] = d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            d[key] = value ?? "";
        }

        // Autostarts (Run-Keys aller angemeldeten Benutzer + Maschine, Autostart-Ordner, Winlogon)
        var runKeys = new List<string>
        {
            @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            @"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        };
        foreach (var h in RegistryUtil.LoadedUserHives())
        {
            runKeys.Add($@"{h}\Software\Microsoft\Windows\CurrentVersion\Run");
            runKeys.Add($@"{h}\Software\Microsoft\Windows\CurrentVersion\RunOnce");
        }
        foreach (var k in runKeys)
            foreach (var (name, value) in RegistryUtil.Values(k))
                Put(CatAutostart, $@"{k}\{name}", value?.ToString());
        foreach (var name in new[] { "Shell", "Userinit" })
            Put(CatAutostart, $@"Winlogon\{name}", RegistryUtil.GetString(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", name));
        var startupDirs = SystemEnv.UserProfiles().Select(p => Path.Combine(p, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"))
            .Append(Path.Combine(PathUtil.ProgramData, @"Microsoft\Windows\Start Menu\Programs\StartUp"));
        foreach (var dir in startupDirs.Where(Directory.Exists))
            foreach (var file in SafeFiles(dir))
                if (!file.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase))
                    Put(CatAutostart, file, Hash(file));

        // Dienste und Treiber
        const string services = @"HKLM\SYSTEM\CurrentControlSet\Services";
        foreach (var svc in RegistryUtil.SubKeys(services))
        {
            string key = $@"{services}\{svc}";
            string? image = RegistryUtil.GetString(key, "ImagePath");
            if (string.IsNullOrWhiteSpace(image)) continue;
            int type = RegistryUtil.GetInt(key, "Type") ?? 0;
            string? dll = RegistryUtil.GetString($@"{key}\Parameters", "ServiceDll");
            Put(type is 1 or 2 ? CatDriver : CatService, svc, dll != null ? $"{image} | {dll}" : image);
        }

        // Geplante Aufgaben (Befehl)
        string tasksDir = Path.Combine(PathUtil.System32, "Tasks");
        foreach (var file in SafeFiles(tasksDir, recursive: true))
        {
            string? command = null;
            try
            {
                var exec = XDocument.Load(file).Descendants().FirstOrDefault(e => e.Name.LocalName == "Exec");
                command = exec == null ? "(COM-Handler)" :
                    $"{exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Command")?.Value} {exec.Elements().FirstOrDefault(e => e.Name.LocalName == "Arguments")?.Value}".Trim();
            }
            catch { }
            Put(CatTask, file[tasksDir.Length..], command);
        }

        // Defender-Ausnahmen
        foreach (var sub in new[] { "Paths", "Extensions", "Processes", "IpAddresses" })
            foreach (var (name, _) in RegistryUtil.Values($@"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\{sub}"))
                Put(CatExclusion, $"{sub}: {name}", "");

        // Konten und Administratoren
        try
        {
            using var acc = new ManagementObjectSearcher("SELECT Name, SID, Disabled FROM Win32_UserAccount WHERE LocalAccount = TRUE");
            foreach (ManagementObject mo in acc.Get()) using (mo) Put(CatAccount, mo["Name"]?.ToString() ?? "?", (mo["Disabled"] as bool? ?? false) ? "deaktiviert" : "aktiv");
        }
        catch { }
        try
        {
            string admins = new System.Security.Principal.SecurityIdentifier("S-1-5-32-544").Translate(typeof(System.Security.Principal.NTAccount)).Value.Split('\\').Last();
            using var grp = new ManagementObjectSearcher($"SELECT PartComponent FROM Win32_GroupUser WHERE GroupComponent=\"Win32_Group.Domain='{Environment.MachineName}',Name='{admins}'\"");
            foreach (ManagementObject mo in grp.Get())
                using (mo)
                {
                    string part = mo["PartComponent"]?.ToString() ?? "";
                    int i = part.IndexOf("Name=\"", StringComparison.Ordinal);
                    if (i >= 0) Put(CatAdmin, part[(i + 6)..].TrimEnd('"'), "");
                }
        }
        catch { }

        // Installierte Programme
        foreach (var p in Scanners.SoftwareScanner.Enumerate())
            Put(CatSoftware, p.Name, p.Version);

        // Stammzertifikate
        foreach (var loc in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
        {
            try
            {
                using var store = new X509Store(StoreName.Root, loc);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                foreach (var c in store.Certificates) Put(CatRootCert, $"{loc}:{c.Thumbprint}", c.Subject);
            }
            catch { }
        }

        // WMI-Abonnements
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();
            foreach (var cls in new[] { "CommandLineEventConsumer", "ActiveScriptEventConsumer" })
            {
                using var w = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT Name FROM {cls}"));
                foreach (ManagementObject mo in w.Get()) using (mo) Put(CatWmi, $"{cls}: {mo["Name"]}", "");
            }
        }
        catch { }

        // Hosts-Datei
        Put(CatHosts, "hosts", Hash(Path.Combine(PathUtil.System32, @"drivers\etc\hosts")));

        // Browser-Erweiterungen (Chromium-Profile)
        foreach (var profile in SystemEnv.UserProfiles())
            foreach (var userData in new[] { @"AppData\Local\Google\Chrome\User Data", @"AppData\Local\Microsoft\Edge\User Data", @"AppData\Local\BraveSoftware\Brave-Browser\User Data" })
            {
                string root = Path.Combine(profile, userData);
                if (!Directory.Exists(root)) continue;
                foreach (var prof in SafeDirs(root).Where(d => Path.GetFileName(d) is "Default" || Path.GetFileName(d).StartsWith("Profile ", StringComparison.Ordinal)))
                    foreach (var ext in SafeDirs(Path.Combine(prof, "Extensions")))
                        Put(CatBrowserExt, $"{Path.GetFileName(Path.GetDirectoryName(Path.GetDirectoryName(prof)))}: {Path.GetFileName(ext)}", "");
            }

        s.Checksum = ComputeChecksum(s);
        return s;
    }

    public static void Save(BaselineSnapshot s) => File.WriteAllText(FilePath, JsonSerializer.Serialize(s, Json));

    public static BaselineSnapshot? Load(string? path = null)
    {
        try
        {
            string p = path ?? FilePath;
            return File.Exists(p) ? JsonSerializer.Deserialize<BaselineSnapshot>(File.ReadAllText(p)) : null;
        }
        catch { return null; }
    }

    /// <summary>Wurde die gespeicherte Baseline nachtraeglich veraendert (z. B. von Malware, um sich zu "legalisieren")?</summary>
    public static bool IsIntact(BaselineSnapshot s) => s.Checksum == null || s.Checksum == ComputeChecksum(s);

    public static List<BaselineChange> Compare(BaselineSnapshot baseline, BaselineSnapshot current)
    {
        var changes = new List<BaselineChange>();
        foreach (var cat in baseline.Categories.Keys.Union(current.Categories.Keys))
        {
            var before = baseline.Categories.GetValueOrDefault(cat) ?? new();
            var after = current.Categories.GetValueOrDefault(cat) ?? new();
            var b = new Dictionary<string, string>(before, StringComparer.OrdinalIgnoreCase);
            var a = new Dictionary<string, string>(after, StringComparer.OrdinalIgnoreCase);
            foreach (var (k, v) in a)
            {
                if (!b.TryGetValue(k, out var old)) changes.Add(new(cat, k, ChangeKind.Added, null, v));
                else if (!string.Equals(old, v, StringComparison.OrdinalIgnoreCase)) changes.Add(new(cat, k, ChangeKind.Changed, old, v));
            }
            foreach (var (k, v) in b)
                if (!a.ContainsKey(k)) changes.Add(new(cat, k, ChangeKind.Removed, v, null));
        }
        return changes;
    }

    // ------------------------------------------------------------------

    private static string ComputeChecksum(BaselineSnapshot s)
    {
        var sb = new StringBuilder();
        foreach (var cat in s.Categories.OrderBy(c => c.Key, StringComparer.Ordinal))
            foreach (var kv in cat.Value.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
                sb.Append(cat.Key).Append('|').Append(kv.Key.ToLowerInvariant()).Append('=').Append(kv.Value).Append('\n');
        sb.Append(s.CreatedAt.ToString("O"));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())));
    }

    private static string? Hash(string file) => Trust.FileTrustService.TryHash(file);

    private static IEnumerable<string> SafeFiles(string dir, bool recursive = false)
    {
        try { return Directory.EnumerateFiles(dir, "*", new System.IO.EnumerationOptions { RecurseSubdirectories = recursive, IgnoreInaccessible = true }).ToList(); }
        catch { return []; }
    }

    private static IEnumerable<string> SafeDirs(string dir)
    {
        try { return Directory.GetDirectories(dir); }
        catch { return []; }
    }
}
