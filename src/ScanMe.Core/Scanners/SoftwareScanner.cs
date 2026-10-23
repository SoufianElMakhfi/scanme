using System.Globalization;
using System.Text.RegularExpressions;
using ScanMe.Core.Engine;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Models;
using ScanMe.Core.Util;

namespace ScanMe.Core.Scanners;

/// <summary>
/// Installierte Programme: unerwuenschte Software, Fernwartung, kuerzliche Installationen
/// und Versionen mit bekannten, aktiv ausgenutzten Sicherheitsluecken.
/// </summary>
public sealed class SoftwareScanner : IScanner
{
    public string Id => "software";
    public string Name => "Installierte Software";
    public string Description => "PUPs, Fernwartungstools, kürzlich installierte Programme und verwundbare Versionen.";
    public bool InQuickScan => true;

    public sealed record InstalledProgram(string Name, string? Version, string? Publisher, DateTime? InstallDate, string? Location, string? Uninstall, string Scope);

    private sealed record VulnRule(Regex Name, Version? FixedIn, int Weight, string Text);

    private static VulnRule V(string name, string? fixedIn, int weight, string text) =>
        new(new Regex(name, RegexOptions.IgnoreCase | RegexOptions.Compiled), fixedIn != null ? Version.Parse(fixedIn) : null, weight, text);

    /// <summary>Software mit aktiv ausgenutzten Luecken bzw. ohne Support (FixedIn = null: jede Version betroffen).</summary>
    private static readonly VulnRule[] VulnRules =
    [
        V(@"^WinRAR", "7.13", 45, "WinRAR vor 7.13 hat aktiv in Phishing-Kampagnen ausgenutzte Lücken (CVE-2023-38831, CVE-2025-8088): Das Öffnen eines präparierten Archivs reicht zur Infektion."),
        V(@"^7-Zip", "25.0", 30, "7-Zip vor 25.00 hat Lücken (u. a. CVE-2025-0411: Umgehung der Internet-Markierung), die in Phishing-Angriffen genutzt wurden."),
        V(@"Adobe Flash Player", null, 55, "Flash Player wird seit 2020 nicht mehr unterstützt und hat zahlreiche ungepatchte Lücken."),
        V(@"Adobe Shockwave", null, 45, "Shockwave wird nicht mehr unterstützt."),
        V(@"Microsoft Silverlight", null, 25, "Silverlight wird seit 2021 nicht mehr unterstützt."),
        V(@"^QuickTime", null, 35, "QuickTime für Windows erhält seit 2016 keine Sicherheitsupdates mehr."),
        V(@"^Java(\(TM\))? [67]\b|^Java [67] Update", null, 45, "Java 6/7 ist seit Jahren ohne Sicherheitsupdates."),
        V(@"^PuTTY", "0.81", 25, "PuTTY vor 0.81 kann private Schlüssel preisgeben (CVE-2024-31497)."),
        V(@"^AnyDesk", "8.0.8", 15, "AnyDesk-Versionen vor 2024 sind von einem Zertifikatsdiebstahl betroffen; Update empfohlen."),
    ];

    public Task ScanAsync(ScanContext ctx)
    {
        var programs = Enumerate();
        ctx.Shared("installed-programs", () => programs);

        foreach (var p in programs)
        {
            ctx.ThrowIfCancelled();
            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Persistence,
                Title = $"Software: {p.Name}",
                Location = p.Location,
            };
            f.Detail("Version", p.Version).Detail("Hersteller", p.Publisher).Detail("Installiert am", p.InstallDate?.ToString("d"))
             .Detail("Installationsort", p.Location).Detail("Deinstallation", p.Uninstall).Detail("Installiert für", p.Scope);

            // --- PUP ---
            var pup = PupCatalog.FindByDisplayName(p.Name);
            if (pup != null)
            {
                f.AddIndicator("PUP", $"Potenziell unerwünschtes Programm: {pup.Name}", 40);
                f.Explanation = pup.Advice;
            }

            // --- Fernwartung / Hacktools ---
            var tool = KnownTools.FindByDisplayName(p.Name);
            if (tool?.Kind is not (KnownTools.ToolKind.RemoteAccess or KnownTools.ToolKind.Tunnel)) tool = null;
            if (tool != null)
            {
                bool recent = p.InstallDate is { } d && (DateTime.Now - d).TotalDays < 30;
                f.AddIndicator("REMOTE_TOOL", $"{KnownTools.KindText(tool.Kind)} installiert{(recent ? " – erst kuerzlich" : "")}. {tool.Note}", recent ? 40 : 20);
                f.Explanation = "Fernwartungsprogramme geben einer anderen Person volle Kontrolle über den PC. Bei Telefonbetrug (falscher Support, falsche Bank) " +
                                "werden Opfer gezielt zur Installation überredet.";
            }

            // --- Verwundbare Versionen ---
            foreach (var rule in VulnRules)
            {
                if (!rule.Name.IsMatch(p.Name)) continue;
                bool affected = rule.FixedIn == null || (TryParseVersion(p.Version ?? p.Name, out var v) && v < rule.FixedIn);
                if (!affected) continue;
                f.AddIndicator("VULN", rule.Text, rule.Weight);
                f.Explanation = rule.Text;
                f.Recommendation = rule.FixedIn != null ? $"Auf Version {rule.FixedIn} oder neuer aktualisieren." : "Deinstallieren – wird nicht mehr benötigt und ist unsicher.";
                f.Category = FindingCategory.SecurityConfig;
            }

            if (f.Indicators.Sum(i => i.Weight) < 15) continue;
            f.Description = $"{p.Name} {p.Version} von {p.Publisher ?? "unbekanntem Hersteller"}" + (p.InstallDate != null ? $", installiert am {p.InstallDate:d}." : ".");
            if (string.IsNullOrEmpty(f.Recommendation))
                f.Recommendation = tool != null
                    ? "Nutzen Sie das Programm bewusst? Falls nicht – oder falls Sie am Telefon dazu gedrängt wurden – deinstallieren und Passwörter von einem anderen Gerät aus ändern."
                    : "Über Einstellungen → Apps → Installierte Apps deinstallieren.";
            ctx.Add(f);
        }

        ReportRecentInstalls(ctx, programs);
        return Task.CompletedTask;
    }

    private void ReportRecentInstalls(ScanContext ctx, List<InstalledProgram> programs)
    {
        var recent = programs.Where(p => p.InstallDate is { } d && (DateTime.Now - d).TotalDays <= 14)
                             .OrderByDescending(p => p.InstallDate).ToList();
        if (recent.Count == 0) return;
        var f = new Finding
        {
            ScannerId = Id,
            Category = FindingCategory.Persistence,
            Title = "Kürzlich installierte Programme (14 Tage)",
            Description = string.Join("; ", recent.Take(30).Select(p => $"{p.InstallDate:d} {p.Name} ({p.Publisher ?? "?"})")),
            Explanation = "Nach einem Phishing-Vorfall oder Support-Anruf hilft diese Zeitleiste zu erkennen, was ohne Ihr Wissen installiert wurde.",
            Recommendation = "Liste durchgehen: Ist alles von Ihnen selbst installiert worden?",
        };
        f.AddIndicator("RECENT_INSTALLS", $"{recent.Count} Programme in den letzten 14 Tagen installiert", 0);
        ctx.Add(f);
    }

    public static List<InstalledProgram> Enumerate()
    {
        var list = new List<InstalledProgram>();
        var roots = new List<(string Key, string Scope)>
        {
            (@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "Alle Benutzer"),
            (@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "Alle Benutzer (32-Bit)"),
        };
        foreach (var hive in RegistryUtil.LoadedUserHives())
            roots.Add(($@"{hive}\Software\Microsoft\Windows\CurrentVersion\Uninstall", RegistryUtil.SidToUser(hive[4..])));

        foreach (var (root, scope) in roots)
        {
            foreach (var sub in RegistryUtil.SubKeys(root))
            {
                string key = $@"{root}\{sub}";
                string? name = RegistryUtil.GetString(key, "DisplayName");
                if (string.IsNullOrWhiteSpace(name)) continue;
                if (RegistryUtil.GetInt(key, "SystemComponent") == 1) continue;
                if (RegistryUtil.GetString(key, "ParentKeyName") != null) continue; // Updates/Unterkomponenten

                DateTime? installed = null;
                string? date = RegistryUtil.GetString(key, "InstallDate");
                if (date != null && DateTime.TryParseExact(date, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)) installed = d;

                list.Add(new InstalledProgram(name.Trim(), RegistryUtil.GetString(key, "DisplayVersion"), RegistryUtil.GetString(key, "Publisher"),
                    installed, RegistryUtil.GetString(key, "InstallLocation"), RegistryUtil.GetString(key, "UninstallString"), scope));
            }
        }
        return list.GroupBy(p => (p.Name, p.Version)).Select(g => g.First()).OrderBy(p => p.Name).ToList();
    }

    private static bool TryParseVersion(string text, out Version version)
    {
        var m = Regex.Match(text, @"(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?");
        version = new Version(0, 0);
        if (!m.Success) return false;
        int Part(int i) => m.Groups[i].Success ? int.Parse(m.Groups[i].Value) : 0;
        version = new Version(Part(1), Part(2), Part(3), Part(4));
        return true;
    }
}
