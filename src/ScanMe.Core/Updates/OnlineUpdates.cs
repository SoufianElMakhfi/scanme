using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;

namespace ScanMe.Core.Updates;

/// <param name="PackageUrl">Release-ZIP fuer diese Architektur (fuer das Ein-Klick-Update), sonst null.</param>
/// <param name="ChecksumsUrl">SHA256SUMS.txt aus demselben Release.</param>
public sealed record UpdateInfo(Version Latest, string Url, string? Notes, string? PackageUrl = null, string? ChecksumsUrl = null);

/// <summary>
/// Online-Funktionen: Programmversion pruefen und signierte Regel-Updates laden.
/// Es werden KEINE Daten vom PC uebertragen – nur zwei anonyme Abrufe bei GitHub.
/// </summary>
public static class OnlineUpdates
{
    public const string Repository = "SoufianElMakhfi/scanme";
    private static readonly string RulesBase = $"https://raw.githubusercontent.com/{Repository}/main/rules/";

    // Reihenfolge wichtig: CurrentVersion muss vor dem HttpClient initialisiert sein (User-Agent).
    public static Version CurrentVersion { get; } =
        Assembly.GetExecutingAssembly().GetName().Version ?? new Version(1, 0, 0);

    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        var c = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
        c.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("ScanMe", CurrentVersion.ToString(3)));
        return c;
    }

    /// <summary>Fragt die neueste Release-Version bei GitHub ab. Null = aktuell oder nicht erreichbar.</summary>
    public static async Task<UpdateInfo?> CheckForUpdateAsync(CancellationToken ct = default)
    {
        try
        {
            using var resp = await Http.GetAsync($"https://api.github.com/repos/{Repository}/releases/latest", ct);
            if (!resp.IsSuccessStatusCode) return null;
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            string tag = doc.RootElement.GetProperty("tag_name").GetString() ?? "";
            if (!Version.TryParse(tag.TrimStart('v', 'V'), out var latest)) return null;
            if (latest <= new Version(CurrentVersion.Major, CurrentVersion.Minor, Math.Max(0, CurrentVersion.Build))) return null;
            string url = doc.RootElement.TryGetProperty("html_url", out var u) ? u.GetString() ?? "" : $"https://github.com/{Repository}/releases";
            string? notes = doc.RootElement.TryGetProperty("body", out var b) ? b.GetString() : null;
            string? Asset(string name) => doc.RootElement.TryGetProperty("assets", out var assets)
                ? assets.EnumerateArray().Where(a => a.GetProperty("name").GetString() == name)
                    .Select(a => a.GetProperty("browser_download_url").GetString()).FirstOrDefault()
                : null;
            return new UpdateInfo(latest, url, notes, Asset(AppUpdater.PackageName), Asset("SHA256SUMS.txt"));
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Laedt das aktuelle Regelpaket samt Signatur. Wird nur uebernommen, wenn die Signatur stimmt,
    /// die Version neuer ist und die App-Version ausreicht. Rueckgabe: Statustext.
    /// </summary>
    public static async Task<string> UpdateRulesAsync(CancellationToken ct = default)
    {
        try
        {
            byte[] data = await Http.GetByteArrayAsync(RulesBase + "rules.json", ct);
            string sig = await Http.GetStringAsync(RulesBase + "rules.json.sig", ct);
            if (!RuleSigning.Verify(data, sig))
                return "Regel-Update abgelehnt: ungültige Signatur.";

            var set = RuleStore.Parse(data);
            RuleStore.UpdateAppWarning(set); // auch wenn die Regeln selbst fuer diese Version zu neu sind
            if (set.Version <= RuleStore.Version)
                return $"Regeln aktuell (Version {RuleStore.Version}).";
            if (set.MinAppVersion != null && Version.TryParse(set.MinAppVersion, out var min) && CurrentVersion < min)
                return $"Neue Regeln (Version {set.Version}) benötigen ScanMe {min} – bitte ScanMe aktualisieren.";

            RuleStore.Apply(set);
            await File.WriteAllBytesAsync(RuleStore.CacheFile, data, ct);
            await File.WriteAllTextAsync(RuleStore.CacheSignature, sig, ct);
            return $"Regeln aktualisiert auf Version {set.Version}.";
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return RuleStore.Version > 0
                ? $"Regelserver nicht erreichbar – verwende gespeicherte Regeln (Version {RuleStore.Version})."
                : "Regelserver nicht erreichbar – nur eingebaute Regeln.";
        }
        catch (Exception ex)
        {
            return "Regel-Update fehlgeschlagen: " + ex.Message;
        }
    }
}
