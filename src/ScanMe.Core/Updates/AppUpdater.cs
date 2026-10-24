using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ScanMe.Core.Actions;
using ScanMe.Core.Trust;

namespace ScanMe.Core.Updates;

/// <summary>
/// Ein-Klick-Update: Release-ZIP laden, pruefen, Dateien austauschen. Bewusst kein Zwangs-Update – ScanMe muss auch
/// offline und bei abgeschalteten Online-Funktionen nutzbar bleiben (etwa nach "PC vom Netz trennen").
///
/// Pruefung vor dem Austausch:
///  1. SHA256 des ZIPs muss zu SHA256SUMS.txt aus demselben Release passen (schuetzt vor defekten Downloads).
///  2. Ist die laufende Version signiert, muss die neue vom selben Herausgeber gueltig signiert sein. Das schuetzt
///     auch vor einem uebernommenen GitHub-Konto – Pruefsummen allein koennte ein Angreifer mit austauschen.
///  3. Die neue Version muss hoeher sein (kein Zurueckspielen alter, fehlerhafter Versionen).
///
/// Austausch: Laufende EXE/DLLs lassen sich unter Windows umbenennen, aber nicht ueberschreiben. Jede Datei wird daher
/// erst zu "*.old" umbenannt, dann ersetzt; bei einem Fehler wird alles zurueckgerollt. Die *.old-Dateien raeumt der
/// naechste Start auf – nur die, die hier angelegt wurden (Liste in cleanup.txt), nie fremde Dateien im Ordner.
/// </summary>
public static class AppUpdater
{
    public static string InstallDir => AppContext.BaseDirectory;
    public static string WorkDir => Path.Combine(AppPaths.DataDir, "Update");
    private static string CleanupListIn(string workDir) => Path.Combine(workDir, "cleanup.txt");

    public static string PackageName =>
        $"ScanMe-win-{(RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "arm64" : "x64")}.zip";

    /// <summary>Laedt Paket und Pruefsummen, prueft alles und entpackt in ein Arbeitsverzeichnis. Rueckgabe: Verzeichnis.</summary>
    public static async Task<string> DownloadAndVerifyAsync(UpdateInfo update, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        if (update.PackageUrl == null || update.ChecksumsUrl == null)
            throw new InvalidOperationException($"Das Release enthält kein {PackageName} oder keine SHA256SUMS.txt.");

        Directory.CreateDirectory(WorkDir);
        string zip = Path.Combine(WorkDir, PackageName);
        progress?.Report($"Lade ScanMe {update.Latest.ToString(3)} herunter …");
        using (var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) })
        {
            http.DefaultRequestHeaders.UserAgent.ParseAdd($"ScanMe/{OnlineUpdates.CurrentVersion.ToString(3)}");
            string sums = await http.GetStringAsync(update.ChecksumsUrl, ct);
            await using (var fs = File.Create(zip))
                await (await http.GetStreamAsync(update.PackageUrl, ct)).CopyToAsync(fs, ct);
            progress?.Report("Prüfe Download …");
            VerifyChecksum(zip, sums);
        }
        string staging = Extract(zip);
        VerifyPackage(staging, InstallDir);
        return staging;
    }

    /// <summary>SHA256SUMS.txt: "HASH  Dateiname" je Zeile.</summary>
    public static void VerifyChecksum(string zip, string sums)
    {
        string name = Path.GetFileName(zip);
        string? expected = sums.Split('\n')
            .Select(l => l.Trim().Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries))
            .Where(p => p.Length == 2 && p[1].Trim().TrimStart('*').Equals(name, StringComparison.OrdinalIgnoreCase))
            .Select(p => p[0])
            .FirstOrDefault();
        if (expected == null) throw new InvalidDataException($"{name} fehlt in SHA256SUMS.txt.");
        string actual;
        using (var fs = File.OpenRead(zip)) actual = Convert.ToHexString(SHA256.HashData(fs));
        if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Prüfsumme stimmt nicht – der Download ist beschädigt oder verändert. Update abgebrochen.");
    }

    public static string Extract(string zip)
    {
        string staging = Path.Combine(WorkDir, "staging");
        if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
        ZipFile.ExtractToDirectory(zip, staging);
        return staging;
    }

    /// <summary>Herausgeber und Version der neuen Dateien pruefen (siehe Klassenbeschreibung).</summary>
    public static void VerifyPackage(string staging, string installDir)
    {
        string newApp = Path.Combine(staging, "ScanMe.exe");
        if (!File.Exists(newApp)) throw new InvalidDataException("Das Update enthält keine ScanMe.exe.");

        var newVersion = FileVersion(newApp);
        var oldVersion = File.Exists(Path.Combine(installDir, "ScanMe.exe")) ? FileVersion(Path.Combine(installDir, "ScanMe.exe")) : OnlineUpdates.CurrentVersion;
        if (newVersion == null || (oldVersion != null && newVersion <= oldVersion))
            throw new InvalidDataException($"Das Update ({newVersion}) ist nicht neuer als die installierte Version ({oldVersion}).");

        var current = FileTrustService.Shared.Get(Path.Combine(installDir, "ScanMe.exe"));
        foreach (var exe in Directory.GetFiles(staging, "*.exe", SearchOption.AllDirectories))
            CheckPublisher(current, FileTrustService.Shared.Get(exe));
    }

    /// <summary>
    /// Ist die laufende Version gueltig signiert, muss jede neue EXE vom selben Herausgeber gueltig signiert sein.
    /// Unsignierte Versionen (vor der Code-Signierung) pruefen nur die Pruefsumme – siehe SIGNING.md.
    /// </summary>
    public static void CheckPublisher(FileTrustInfo current, FileTrustInfo candidate)
    {
        if (current.Signature != SignatureState.Valid) return;
        if (candidate.Signature != SignatureState.Valid || !string.Equals(candidate.Signer, current.Signer, StringComparison.Ordinal))
            throw new InvalidDataException($"{Path.GetFileName(candidate.Path)} ist nicht vom selben Herausgeber signiert " +
                                           $"({candidate.Signer ?? "unsigniert"} statt {current.Signer}). Update abgebrochen.");
    }

    private static Version? FileVersion(string path) =>
        Version.TryParse(FileVersionInfo.GetVersionInfo(path).FileVersion, out var v) ? new Version(v.Major, v.Minor, Math.Max(0, v.Build)) : null;

    /// <summary>Tauscht alle Dateien aus dem Arbeitsverzeichnis aus; bei einem Fehler wird alles zurueckgerollt.</summary>
    /// <param name="workDir">Ablage der Aufraeumliste; Standard <see cref="WorkDir"/> (Tests nutzen einen eigenen Ordner).</param>
    public static void Apply(string staging, string installDir, string? workDir = null)
    {
        var done = new List<(string Target, string? Backup)>();
        try
        {
            foreach (var src in Directory.GetFiles(staging, "*", SearchOption.AllDirectories))
            {
                string target = Path.Combine(installDir, Path.GetRelativePath(staging, src));
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                string? backup = null;
                if (File.Exists(target))
                {
                    backup = FreeBackupName(target);
                    File.Move(target, backup); // klappt auch bei laufender EXE/geladener DLL
                }
                done.Add((target, backup));
                File.Copy(src, target);
            }
        }
        catch
        {
            foreach (var (target, backup) in Enumerable.Reverse(done))
            {
                try { if (File.Exists(target)) File.Delete(target); } catch { }
                try { if (backup != null) File.Move(backup, target); } catch { }
            }
            throw;
        }

        string list = CleanupListIn(workDir ?? WorkDir);
        Directory.CreateDirectory(Path.GetDirectoryName(list)!);
        File.AppendAllLines(list, done.Where(d => d.Backup != null).Select(d => d.Backup!));
        try { Directory.Delete(staging, recursive: true); } catch { }
    }

    private static string FreeBackupName(string target)
    {
        for (int i = 0; ; i++)
        {
            string name = target + (i == 0 ? ".old" : $".old{i}");
            if (!File.Exists(name)) return name;
            try { File.Delete(name); return name; } catch { } // noch geladen – naechste Nummer
        }
    }

    /// <summary>Beim Start: alte Dateien vom letzten Update loeschen. Noch gesperrte bleiben fuer den naechsten Start.</summary>
    public static void CleanupAfterUpdate(string? workDir = null)
    {
        try
        {
            string list = CleanupListIn(workDir ?? WorkDir);
            if (!File.Exists(list)) return;
            var remaining = File.ReadAllLines(list)
                .Where(p => p.Length > 0 && File.Exists(p))
                .Where(p => { try { File.Delete(p); return false; } catch { return true; } })
                .ToList();
            if (remaining.Count == 0) File.Delete(list); else File.WriteAllLines(list, remaining);
            string zip = Path.Combine(workDir ?? WorkDir, PackageName);
            if (File.Exists(zip)) File.Delete(zip);
        }
        catch { }
    }

    /// <summary>Startet die neue Version (gleiche Rechte, keine UAC-Abfrage, da ScanMe bereits als Admin laeuft).</summary>
    public static void Restart(string exeName = "ScanMe.exe") =>
        Process.Start(new ProcessStartInfo(Path.Combine(InstallDir, exeName)) { UseShellExecute = false, WorkingDirectory = InstallDir });
}
