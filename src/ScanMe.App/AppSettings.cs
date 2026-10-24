using System.Text.Json;
using ScanMe.Core.Actions;
using ScanMe.Core.Engine;

namespace ScanMe.App;

public sealed class AppSettings
{
    public bool UseDefender { get; set; } = true;
    public int EventLogDays { get; set; } = 30;
    public List<string> DisabledScanners { get; set; } = new();
    public List<string> ExtraPaths { get; set; } = new();
    public bool StartMonitorOnLaunch { get; set; }
    public bool MinimizeToTray { get; set; } = true;

    /// <summary>Update-Prüfung und signierte Regel-Updates (nur anonyme Abrufe bei GitHub).</summary>
    public bool OnlineFeatures { get; set; } = true;

    /// <summary>Version, für die der Haftungshinweis bestätigt wurde.</summary>
    public string? DisclaimerAccepted { get; set; }

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(AppPaths.SettingsFile))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(AppPaths.SettingsFile)) ?? new();
        }
        catch { }
        return new();
    }

    public void Save() =>
        File.WriteAllText(AppPaths.SettingsFile, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));

    public ScanOptions ToScanOptions(ScanProfile profile)
    {
        var o = new ScanOptions { Profile = profile, UseDefender = UseDefender, EventLogDays = EventLogDays };
        foreach (var s in DisabledScanners) o.DisabledScanners.Add(s);
        o.ExtraPaths.AddRange(ExtraPaths.Where(Directory.Exists));
        return o;
    }
}
