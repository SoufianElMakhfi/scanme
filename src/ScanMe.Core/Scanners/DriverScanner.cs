using System.Text;
using ScanMe.Core.Engine;
using ScanMe.Core.Models;
using ScanMe.Core.Native;
using ScanMe.Core.Trust;
using ScanMe.Core.Util;

namespace ScanMe.Core.Scanners;

/// <summary>
/// Kernel-Treiber laufen mit hoechsten Rechten. Unsignierte oder bekannt verwundbare Treiber
/// werden von Rootkits und Ransomware ("Bring Your Own Vulnerable Driver") genutzt.
/// </summary>
public sealed class DriverScanner : IScanner
{
    public string Id => "drivers";
    public string Name => "Treiber & Kernel";
    public string Description => "Unsignierte und verwundbare Treiber, Testsignaturmodus, Speicherintegrität.";
    public bool InQuickScan => true;

    /// <summary>Auswahl bekannt verwundbarer Treiber (loldrivers.io), die zum Abschalten von Sicherheitssoftware missbraucht werden.</summary>
    private static readonly Dictionary<string, string> VulnerableDrivers = new(StringComparer.OrdinalIgnoreCase)
    {
        ["RTCore64.sys"] = "MSI Afterburner (CVE-2019-16098)",
        ["RTCore32.sys"] = "MSI Afterburner (CVE-2019-16098)",
        ["dbutil_2_3.sys"] = "Dell BIOS-Utility (CVE-2021-21551)",
        ["gdrv.sys"] = "Gigabyte (CVE-2018-19320)",
        ["AsrDrv101.sys"] = "ASRock", ["AsrDrv102.sys"] = "ASRock", ["AsrDrv103.sys"] = "ASRock", ["AsrDrv104.sys"] = "ASRock", ["AsrDrv106.sys"] = "ASRock",
        ["WinRing0x64.sys"] = "WinRing0 (Lüfter-/Monitoring-Tools, CVE-2020-14979)",
        ["WinRing0.sys"] = "WinRing0 (CVE-2020-14979)",
        ["iqvw64e.sys"] = "Intel Netzwerkdiagnose (CVE-2015-2291)",
        ["capcom.sys"] = "Capcom Anti-Cheat",
        ["aswArPot.sys"] = "Avast Anti-Rootkit (von Ransomware missbraucht)",
        ["zamguard64.sys"] = "Zemana (von Terminator-Tool missbraucht)",
        ["zam64.sys"] = "Zemana",
        ["truesight.sys"] = "RogueKiller (von Ransomware missbraucht)",
        ["mhyprot2.sys"] = "Genshin Impact Anti-Cheat (von Ransomware missbraucht)",
        ["kprocesshacker.sys"] = "Process Hacker (alt)",
        ["PROCEXP152.SYS"] = "Process Explorer (von AuKill missbraucht)",
        ["ene.sys"] = "ENE RGB (CVE-2023-41444)",
        ["atillk64.sys"] = "ATI", ["AMDRyzenMasterDriver.sys"] = "AMD Ryzen Master (CVE-2020-12928)",
        ["NTIOLib_X64.sys"] = "MSI", ["Bs_Def64.sys"] = "Biostar", ["GLCKIO2.sys"] = "ASRock RGB", ["inpoutx64.sys"] = "InpOut",
        ["HW64.sys"] = "Marvin Hardware Access", ["physmem.sys"] = "Physical Memory Access", ["speedfan.sys"] = "SpeedFan",
        ["viragt64.sys"] = "TG Soft", ["rwdrv.sys"] = "RWEverything", ["echo_driver.sys"] = "Echo Anti-Cheat",
    };

    public Task ScanAsync(ScanContext ctx)
    {
        ScanBootConfiguration(ctx);

        // Treiberdienste (Pfad -> Dienstname), damit auch geladene Treiber deaktiviert werden koennen
        const string services = @"HKLM\SYSTEM\CurrentControlSet\Services";
        var driverServices = new List<(string Service, string Path, bool Disabled)>();
        foreach (var svc in RegistryUtil.SubKeys(services))
        {
            string key = $@"{services}\{svc}";
            if ((RegistryUtil.GetInt(key, "Type") ?? 0) is not (1 or 2)) continue;
            string? image = RegistryUtil.GetString(key, "ImagePath");
            if (string.IsNullOrWhiteSpace(image)) continue;
            driverServices.Add((svc, PathUtil.Normalize(image), RegistryUtil.GetInt(key, "Start") == 4));
        }
        var serviceByPath = driverServices.GroupBy(d => d.Path, StringComparer.OrdinalIgnoreCase)
                                          .ToDictionary(g => g.Key, g => g.First().Service, StringComparer.OrdinalIgnoreCase);

        ctx.Status("Geladene Treiber …");
        var loaded = LoadedDrivers();
        foreach (var path in loaded)
        {
            ctx.ThrowIfCancelled();
            AssessDriver(ctx, path, loaded: true, service: serviceByPath.GetValueOrDefault(path));
        }

        ctx.Status("Treiberdienste …");
        foreach (var (svc, path, disabled) in driverServices)
        {
            if (disabled || loaded.Contains(path)) continue;
            if (!PathUtil.IsUnderWindowsDirectory(path)) AssessDriver(ctx, path, loaded: false, service: svc);
        }
        return Task.CompletedTask;
    }

    private static HashSet<string> LoadedDrivers()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var bases = new IntPtr[2048];
        if (!NativeMethods.EnumDeviceDrivers(bases, bases.Length * IntPtr.Size, out int needed)) return result;
        int count = Math.Min(needed / IntPtr.Size, bases.Length);
        var sb = new StringBuilder(1024);
        for (int i = 0; i < count; i++)
        {
            sb.Clear();
            if (NativeMethods.GetDeviceDriverFileName(bases[i], sb, sb.Capacity) > 0)
                result.Add(PathUtil.Normalize(sb.ToString()));
        }
        return result;
    }

    private void AssessDriver(ScanContext ctx, string path, bool loaded, string? service = null)
    {
        string name = Path.GetFileName(path);
        var info = ctx.Trust.Get(path);
        var f = new Finding
        {
            ScannerId = Id,
            Category = FindingCategory.Driver,
            Title = $"Treiber: {name}",
            FilePath = path,
        };
        f.Detail("Geladen", loaded ? "ja" : "nein (registriert)").Detail("Dienst", service);
        ExecutableAssessor.AddDetails(f, info);

        if (!info.Exists)
        {
            if (!loaded) return; // verwaiste Treiberdienste sind haeufig und harmlos
            f.AddIndicator("DRV_NO_FILE", "Geladener Treiber, dessen Datei nicht mehr existiert", 40);
        }
        else if (info.Signature == SignatureState.NotSigned)
            f.AddIndicator("DRV_UNSIGNED", "Unsignierter Kernel-Treiber", 55);
        else if (info.Signature == SignatureState.Invalid)
            f.AddIndicator("DRV_BAD_SIG", "Treiber mit ungültiger Signatur: " + info.SignatureStatusText, 60);
        else if (info.IsMicrosoftSigned)
            f.IsProtected = true;

        string? original = info.OriginalFilename;
        if (VulnerableDrivers.TryGetValue(name, out var vendor) || (original != null && VulnerableDrivers.TryGetValue(original, out vendor)))
            f.AddIndicator("DRV_VULNERABLE", $"Bekannt verwundbarer Treiber ({vendor}) – kann zum Abschalten von Sicherheitssoftware missbraucht werden", 40);

        // Umbenannter Treiber: Krypto-Miner bringen z. B. WinRing0.sys unter Tarnnamen mit.
        if (original != null && !original.Equals(name, StringComparison.OrdinalIgnoreCase)
            && Path.GetExtension(original).Equals(".sys", StringComparison.OrdinalIgnoreCase) && !info.IsMicrosoftSigned)
        {
            bool vulnerable = VulnerableDrivers.ContainsKey(original);
            // Hersteller benennen eigene signierte Treiber oft um (NTIOLib -> NTIOLib_X64) – nur bei verwundbaren Treibern wirklich relevant.
            f.AddIndicator("DRV_RENAMED", $"Treiber wurde umbenannt: eigentlich \"{original}\", hier als \"{name}\"",
                vulnerable ? 45 : info.Signature == SignatureState.Valid ? 5 : 20);
            if (original.StartsWith("WinRing0", StringComparison.OrdinalIgnoreCase))
                f.AddIndicator("DRV_MINER", "WinRing0 unter falschem Namen ist ein typisches Merkmal von Krypto-Minern (XMRig nutzt ihn für CPU-Register)", 25);
        }
        if (service != null) f.Detail("Dienstname", service);

        var loc = Knowledge.LocationClassifier.Classify(path);
        if (Knowledge.LocationClassifier.IsUserWritable(loc))
            f.AddIndicator("DRV_USER_PATH", "Treiber liegt in einem benutzerbeschreibbaren Ordner", 40);

        if (f.Indicators.Sum(i => i.Weight) < 15) return;
        f.Description = $"Kernel-Treiber {path}" + (info.Signer != null ? $", signiert von {info.Signer}." : ".");
        f.Explanation = "Treiber laufen im Windows-Kern mit uneingeschränkten Rechten. Rootkits verstecken sich so; Ransomware lädt verwundbare, aber " +
                        "signierte Treiber, um Antivirensoftware zu beenden ('BYOVD').";
        f.Recommendation = f.Indicators.Any(i => i.Code is "DRV_RENAMED" or "DRV_MINER")
            ? "Der Treiber gehört sehr wahrscheinlich zu Schadsoftware. Treiberdienst deaktivieren, Datei und das zugehörige Programm im selben Ordner in Quarantäne verschieben, " +
              "anschließend Defender-Offline-Scan ausführen. Da das Programm mit Adminrechten lief, Passwörter von einem anderen Gerät aus ändern."
            : f.Indicators.Any(i => i.Code == "DRV_VULNERABLE")
            ? "Zugehöriges Programm aktualisieren oder deinstallieren. 'Speicherintegrität' und die Microsoft-Treiber-Sperrliste aktivieren."
            : "Herkunft klären. Unbekannte, unsignierte Treiber sind ein starkes Rootkit-Indiz – Defender-Offline-Scan ausführen.";
        f.Actions.Add(new RemediationAction { Kind = RemediationKind.OpenLocation, Label = "Speicherort öffnen", Target = path, RequiresConfirmation = false });
        if (service != null && !f.IsProtected)
            f.Actions.Insert(0, new RemediationAction { Kind = RemediationKind.DisableService, Label = "Treiberdienst deaktivieren", Target = service });
        if (info.Exists && !info.IsMicrosoftSigned)
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.QuarantineFile, Label = "In Quarantäne verschieben", Target = path });
        ctx.Add(f);
    }

    private void ScanBootConfiguration(ScanContext ctx)
    {
        string options = RegistryUtil.GetString(@"HKLM\SYSTEM\CurrentControlSet\Control", "SystemStartOptions")?.ToUpperInvariant() ?? "";
        if (options.Contains("TESTSIGNING"))
            Add(ctx, "Testsignaturmodus aktiv", 50, "Windows lädt auch Treiber mit Testsignaturen.",
                "Damit können beliebige Treiber (auch Rootkits) geladen werden. Manchmal für Entwicklung/Modding aktiviert.",
                "Als Administrator ausführen: bcdedit /set testsigning off – danach neu starten.");
        if (options.Contains("DISABLE_INTEGRITY_CHECKS") || options.Contains("NOINTEGRITYCHECKS"))
            Add(ctx, "Treiber-Signaturprüfung deaktiviert", 60, "Die Integritätsprüfung für Treiber ist abgeschaltet.",
                "Unsignierte Kernel-Treiber (Rootkits) können geladen werden.",
                "bcdedit /set nointegritychecks off – danach neu starten.");

        if (RegistryUtil.GetInt(@"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable") == 0)
            Add(ctx, "Sperrliste für verwundbare Treiber deaktiviert", 15, "Die Microsoft-Sperrliste für bekannte verwundbare Treiber ist aus.",
                "Die Sperrliste verhindert BYOVD-Angriffe.", "Windows-Sicherheit → Gerätesicherheit → Kernisolierung → 'Sperrliste für anfällige Microsoft-Treiber' einschalten.");

        if (RegistryUtil.GetInt(@"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled") is 0 or null)
            Add(ctx, "Speicherintegrität (HVCI) ist aus", 8, "Die hypervisorgeschützte Codeintegrität ist nicht aktiv.",
                "Sie verhindert, dass bösartiger Code in den Windows-Kern eingeschleust wird.",
                "Windows-Sicherheit → Gerätesicherheit → Kernisolierung → Speicherintegrität (inkompatible Treiber werden dort angezeigt).");
    }

    private void Add(ScanContext ctx, string title, int weight, string desc, string expl, string rec)
    {
        var f = new Finding { ScannerId = Id, Category = FindingCategory.Driver, Title = title, Description = desc, Explanation = expl, Recommendation = rec };
        f.AddIndicator("CFG", title, weight);
        ctx.Add(f);
    }
}
