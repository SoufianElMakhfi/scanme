using System.Text.Json;
using ScanMe.Core.Engine;
using ScanMe.Core.Models;
using ScanMe.Core.Util;

namespace ScanMe.Core.Scanners;

/// <summary>
/// Browser sind das Haupteinfallstor fuer Phishing: boesartige Erweiterungen, Hijacking per Richtlinie,
/// Benachrichtigungs-Spam ("Ihr PC ist infiziert") und manipulierte Verknuepfungen.
/// </summary>
public sealed class BrowserScanner : IScanner
{
    public string Id => "browser";
    public string Name => "Browser";
    public string Description => "Erweiterungen, Richtlinien-Hijacking, Benachrichtigungs-Spam und manipulierte Browser-Verknuepfungen.";
    public bool InQuickScan => true;

    private sealed record Browser(string Name, string UserDataRelative, string PolicyKey);

    private static readonly Browser[] Chromium =
    [
        new("Google Chrome", @"AppData\Local\Google\Chrome\User Data", @"SOFTWARE\Policies\Google\Chrome"),
        new("Microsoft Edge", @"AppData\Local\Microsoft\Edge\User Data", @"SOFTWARE\Policies\Microsoft\Edge"),
        new("Brave", @"AppData\Local\BraveSoftware\Brave-Browser\User Data", @"SOFTWARE\Policies\BraveSoftware\Brave"),
        new("Vivaldi", @"AppData\Local\Vivaldi\User Data", @"SOFTWARE\Policies\Vivaldi"),
        new("Opera", @"AppData\Roaming\Opera Software", @"SOFTWARE\Policies\Opera Software\Opera"),
    ];

    /// <summary>Weit verbreitete, seriöse Erweiterungen (Chrome-Web-Store-IDs).</summary>
    private static readonly HashSet<string> KnownGood = new(StringComparer.OrdinalIgnoreCase)
    {
        "cjpalhdlnbpafiamejdnhcphjbkeiagm", // uBlock Origin
        "ddkjiahejlhfcafbddmgiahcphecmpfh", // uBlock Origin Lite
        "nngceckbapebfimnlniiiahkandclblb", // Bitwarden
        "aeblfdkhhhdcdjpifhhbdiojplfjncoa", // 1Password
        "hdokiejnpimakedhajhdlcegeplioahd", // LastPass
        "ghbmnnjooekpmoecnnnilnnbdlolhkhi", // Google Docs Offline
        "aapbdbdomjkkjkaonfhkkikfgjllcleb", // Google Translate
        "kbfnbcaeplbcioakkpcpgfkobkghlhen", // Grammarly
        "cfhdojbkjhnklbpkdaibdccddilifddb", // Adblock Plus
        "gighmmpiobklfepjocnamgkkbiglidom", // AdBlock
        "eimadpbcbfnmbkopoojfekhnkhdbieeh", // Dark Reader
        "nkbihfbeogaeaoehlefnkodbefgpgknn", // MetaMask
        "fmkadmapgofadopljbjfkapdkoienihi", // React DevTools
        "nmmhkkegccagdldgiimedpiccmgmieda", // Chrome Web Store Payments
        "mhjfbmdgcfjbbpaeojofohoefgiehjai", // Chrome PDF Viewer
        "pkedcjkdefgpdelpbcmbmeomcjbeemfm", // Chrome Media Router
        "odfafepnkmbhccpbejgmiehpchacaeak", // uBlock Origin (Edge)
        "jbleaibbmcmkekobljldplhjldnbpbmb", // Microsoft Editor? (Edge)
    };

    private static readonly string[] DangerousPermissions =
        ["<all_urls>", "*://*/*", "http://*/*", "https://*/*", "webRequest", "webRequestBlocking", "cookies", "debugger", "proxy",
         "nativeMessaging", "management", "clipboardRead", "history", "scripting", "tabs", "privacy", "downloads", "declarativeNetRequestWithHostAccess"];

    public Task ScanAsync(ScanContext ctx)
    {
        _extensions.Clear();
        ctx.Status("Browser-Richtlinien …");
        foreach (var b in Chromium) ScanPolicies(ctx, b);

        foreach (var profileRoot in SystemEnv.UserProfiles())
        {
            foreach (var b in Chromium)
            {
                ctx.ThrowIfCancelled();
                string userData = Path.Combine(profileRoot, b.UserDataRelative);
                if (!Directory.Exists(userData)) continue;
                ctx.Status($"{b.Name}: Erweiterungen …");
                foreach (var profileDir in ChromiumProfiles(userData))
                {
                    var prefs = LoadJson(Path.Combine(profileDir, "Secure Preferences")) ?? LoadJson(Path.Combine(profileDir, "Preferences"));
                    var plainPrefs = LoadJson(Path.Combine(profileDir, "Preferences"));
                    ScanChromiumExtensions(ctx, b, profileDir, prefs);
                    if (plainPrefs != null) ScanNotifications(ctx, b, profileDir, plainPrefs.Value);
                }
            }
            ScanFirefox(ctx, profileRoot);
            ScanBrowserShortcuts(ctx, profileRoot);
        }
        foreach (var f in _extensions.Values) ctx.Add(f);
        return Task.CompletedTask;
    }

    /// <summary>Eine Erweiterung, die in mehreren Profilen steckt, wird nur einmal gemeldet.</summary>
    private readonly Dictionary<string, Finding> _extensions = new(StringComparer.OrdinalIgnoreCase);

    private static IEnumerable<string> ChromiumProfiles(string userData)
    {
        IEnumerable<string> dirs;
        try { dirs = Directory.GetDirectories(userData); } catch { yield break; }
        foreach (var d in dirs)
        {
            string n = Path.GetFileName(d);
            if (n == "Default" || n.StartsWith("Profile ", StringComparison.Ordinal) || n == "Opera Stable" || n == "Opera GX Stable")
                yield return d;
        }
    }

    private static JsonElement? LoadJson(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var doc = JsonDocument.Parse(fs, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            return doc.RootElement.Clone();
        }
        catch { return null; }
    }

    private static JsonElement? Path_(JsonElement? root, params string[] path)
    {
        var cur = root;
        foreach (var p in path)
        {
            if (cur is not { ValueKind: JsonValueKind.Object } o || !o.TryGetProperty(p, out var next)) return null;
            cur = next;
        }
        return cur;
    }

    // ------------------------------------------------------------------
    // Richtlinien
    // ------------------------------------------------------------------

    private void ScanPolicies(ScanContext ctx, Browser b)
    {
        foreach (var hive in new[] { "HKLM" }.Concat(RegistryUtil.LoadedUserHives()))
        {
            string key = $@"{hive}\{b.PolicyKey}";
            // Zwangsinstallierte Erweiterungen
            foreach (var (_, value) in RegistryUtil.Values($@"{key}\ExtensionInstallForcelist"))
            {
                if (value is not string entry) continue;
                var parts = entry.Split(';');
                string id = parts[0].Trim();
                string? updateUrl = parts.Length > 1 ? parts[1].Trim() : null;
                bool store = updateUrl == null || updateUrl.Contains("clients2.google.com") || updateUrl.Contains("edge.microsoft.com");
                var f = new Finding
                {
                    ScannerId = Id,
                    Category = FindingCategory.Browser,
                    Title = $"{b.Name}: Erweiterung per Richtlinie erzwungen ({id})",
                    Location = $@"{key}\ExtensionInstallForcelist",
                    Description = $"Die Erweiterung {id} wird per Gruppenrichtlinie zwangsinstalliert" + (store ? "." : $" – von {updateUrl}."),
                    Explanation = "Zwangsinstallierte Erweiterungen lassen sich im Browser nicht entfernen. In Firmen normal – auf Privat-PCs ein typisches Zeichen fuer " +
                                  "Browser-Hijacker und Stealer, die so Passwoerter und Cookies abgreifen.",
                    Recommendation = "Wenn das kein Firmen-PC ist: Richtlinieneintrag entfernen, Browser neu starten und Passwoerter aendern.",
                };
                f.AddIndicator("FORCED_EXT", "Erweiterung per Richtlinie erzwungen", store ? 35 : 60);
                f.Detail("Erweiterungs-ID", id).Detail("Update-URL", updateUrl);
                ctx.Add(f);
            }

            // Startseite/Suche/Proxy per Richtlinie
            var hijack = new List<string>();
            foreach (var name in new[] { "HomepageLocation", "NewTabPageLocation", "DefaultSearchProviderSearchURL", "DefaultSearchProviderName", "ProxyServer", "ProxyPacUrl" })
            {
                string? v = RegistryUtil.GetString(key, name);
                if (!string.IsNullOrWhiteSpace(v)) hijack.Add($"{name} = {v}");
            }
            foreach (var (_, v) in RegistryUtil.Values($@"{key}\RestoreOnStartupURLs"))
                if (v is string s) hijack.Add($"Startseite = {s}");

            if (hijack.Count > 0)
            {
                var f = new Finding
                {
                    ScannerId = Id,
                    Category = FindingCategory.Browser,
                    Title = $"{b.Name}: Einstellungen per Richtlinie festgelegt",
                    Location = key,
                    Description = string.Join("; ", hijack),
                    Explanation = "Browser-Hijacker setzen Startseite, Suchmaschine oder Proxy per Richtlinie, damit der Nutzer sie nicht aendern kann. " +
                                  "Der Browser zeigt dann 'Wird von Ihrer Organisation verwaltet'.",
                    Recommendation = "Wenn das kein Firmen-PC ist: Richtlinienschluessel entfernen.",
                };
                bool proxy = hijack.Any(h => h.StartsWith("Proxy"));
                f.AddIndicator("POLICY_HIJACK", "Browser-Einstellungen per Richtlinie erzwungen", proxy ? 50 : 35);
                ctx.Add(f);
            }
        }
    }

    // ------------------------------------------------------------------
    // Chromium-Erweiterungen
    // ------------------------------------------------------------------

    private void ScanChromiumExtensions(ScanContext ctx, Browser b, string profileDir, JsonElement? prefs)
    {
        string extRoot = Path.Combine(profileDir, "Extensions");
        if (!Directory.Exists(extRoot)) return;
        var settings = Path_(prefs, "extensions", "settings");

        foreach (var extDir in SafeDirs(extRoot))
        {
            string id = Path.GetFileName(extDir);
            string? versionDir = SafeDirs(extDir).OrderByDescending(d => d, StringComparer.Ordinal).FirstOrDefault();
            if (versionDir == null) continue;
            var manifest = LoadJson(Path.Combine(versionDir, "manifest.json"));
            if (manifest == null) continue;

            string name = ResolveName(manifest.Value, versionDir) ?? id;
            var perms = new List<string>();
            foreach (var permKey in new[] { "permissions", "host_permissions", "optional_permissions" })
                if (Path_(manifest, permKey) is { ValueKind: JsonValueKind.Array } arr)
                    perms.AddRange(arr.EnumerateArray().Where(p => p.ValueKind == JsonValueKind.String).Select(p => p.GetString()!));
            if (Path_(manifest, "content_scripts") is { ValueKind: JsonValueKind.Array } cs)
                foreach (var s in cs.EnumerateArray())
                    if (s.TryGetProperty("matches", out var m) && m.ValueKind == JsonValueKind.Array)
                        perms.AddRange(m.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).Select(x => x == "<all_urls>" || x.StartsWith("*://*/") ? x : ""));
            perms = perms.Where(p => p.Length > 0).Distinct().ToList();

            var setting = settings is { ValueKind: JsonValueKind.Object } so && so.TryGetProperty(id, out var st) ? st : (JsonElement?)null;
            int location = setting is { } s1 && s1.TryGetProperty("location", out var loc) && loc.TryGetInt32(out var li) ? li : -1;
            bool fromStore = setting is { } s2 && s2.TryGetProperty("from_webstore", out var fw) && fw.ValueKind == JsonValueKind.True;
            string? updateUrl = Path_(manifest, "update_url")?.GetString();
            bool storeUpdate = updateUrl != null && (updateUrl.Contains("clients2.google.com") || updateUrl.Contains("edge.microsoft.com"));
            if (location is 5 or 10) continue; // Browser-Komponenten

            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Browser,
                Title = $"{b.Name}-Erweiterung: {name}",
                Location = versionDir,
            };
            f.Detail("Erweiterungs-ID", id).Detail("Version", Path.GetFileName(versionDir)).Detail("Profil", profileDir)
             .Detail("Berechtigungen", string.Join(", ", perms.Take(25))).Detail("Update-URL", updateUrl);

            if (location == 4)
                f.AddIndicator("EXT_UNPACKED", "Entpackt geladen (Entwicklermodus) – nicht aus einem Store", 35);
            else if (!fromStore && !storeUpdate)
                f.AddIndicator("EXT_SIDELOADED", "Nicht aus dem offiziellen Store installiert", 30);

            var dangerous = perms.Where(p => DangerousPermissions.Contains(p)).ToList();
            bool allSites = dangerous.Any(p => p.Contains("*") || p == "<all_urls>");
            if (allSites && dangerous.Any(p => p is "cookies" or "webRequest" or "webRequestBlocking" or "debugger" or "proxy" or "scripting"))
                f.AddIndicator("EXT_POWERFUL", "Darf auf allen Webseiten mitlesen und eingreifen (inkl. Cookies/Netzwerkverkehr)", 15);
            if (dangerous.Contains("debugger")) f.AddIndicator("EXT_DEBUGGER", "Berechtigung 'debugger' – volle Kontrolle ueber Tabs", 15);
            if (dangerous.Contains("proxy")) f.AddIndicator("EXT_PROXY", "Darf den Proxy setzen – kann Datenverkehr umleiten", 15);
            if (dangerous.Contains("nativeMessaging")) f.AddIndicator("EXT_NATIVE", "Kommuniziert mit Programmen ausserhalb des Browsers", 5);
            if (KnownGood.Contains(id)) f.AddIndicator("EXT_KNOWN_GOOD", "Bekannte, weit verbreitete Erweiterung", -40);

            int score = f.Indicators.Sum(i => i.Weight);
            f.Description = $"Erweiterung \"{name}\" ({id}) mit {perms.Count} Berechtigung(en).";
            f.Explanation = "Browser-Erweiterungen sehen alles, was Sie auf Webseiten eingeben – auch Passwoerter und Bankdaten. " +
                            "Boesartige Erweiterungen sind eine der haeufigsten Ursachen fuer gestohlene Konten.";
            f.Recommendation = score >= 35
                ? "Erweiterung entfernen, wenn Sie sie nicht bewusst installiert haben (Browser → Erweiterungen verwalten). Danach Passwoerter aendern."
                : "Pruefen, ob Sie die Erweiterung kennen und noch nutzen. Ungenutzte Erweiterungen entfernen.";
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.OpenLocation, Label = "Ordner oeffnen", Target = versionDir, RequiresConfirmation = false });

            // Jede Erweiterung erscheint im Bericht (mindestens als Info) – volle Transparenz.
            string key = $"{b.Name}|{id}";
            if (_extensions.TryGetValue(key, out var existing))
            {
                existing.Details["Profil"] = existing.Details["Profil"] + " | " + profileDir;
                if (score > existing.Indicators.Sum(i => i.Weight)) _extensions[key] = f;
            }
            else
            {
                _extensions[key] = f;
            }
        }
    }

    private static string? ResolveName(JsonElement manifest, string dir)
    {
        string? name = manifest.TryGetProperty("name", out var n) ? n.GetString() : null;
        if (name == null || !name.StartsWith("__MSG_", StringComparison.Ordinal)) return name;
        string key = name[6..].TrimEnd('_');
        string locale = manifest.TryGetProperty("default_locale", out var dl) ? dl.GetString() ?? "en" : "en";
        foreach (var loc in new[] { "de", locale, "en", "en_US" })
        {
            var messages = LoadJson(Path.Combine(dir, "_locales", loc, "messages.json"));
            if (messages is { ValueKind: JsonValueKind.Object } m)
                foreach (var prop in m.EnumerateObject())
                    if (prop.Name.Equals(key, StringComparison.OrdinalIgnoreCase) && prop.Value.TryGetProperty("message", out var msg))
                        return msg.GetString();
        }
        return name;
    }

    private static IEnumerable<string> SafeDirs(string dir)
    {
        try { return Directory.GetDirectories(dir); }
        catch { return []; }
    }

    // ------------------------------------------------------------------
    // Benachrichtigungen
    // ------------------------------------------------------------------

    private static readonly string[] TrustedNotificationHosts =
        ["google.com", "youtube.com", "whatsapp.com", "discord.com", "x.com", "twitter.com", "facebook.com", "instagram.com", "linkedin.com",
         "outlook", "office.com", "live.com", "microsoft.com", "slack.com", "teams", "telegram.org", "github.com", "notion.so", "gmail", "spotify.com", "reddit.com"];

    private void ScanNotifications(ScanContext ctx, Browser b, string profileDir, JsonElement prefs)
    {
        if (Path_(prefs, "profile", "content_settings", "exceptions", "notifications") is not { ValueKind: JsonValueKind.Object } n) return;
        var allowed = n.EnumerateObject()
            .Where(p => p.Value.TryGetProperty("setting", out var s) && s.TryGetInt32(out var v) && v == 1)
            .Select(p => p.Name.Split(',')[0])
            .Where(site => !TrustedNotificationHosts.Any(t => site.Contains(t, StringComparison.OrdinalIgnoreCase)))
            .ToList();
        if (allowed.Count == 0) return;

        var f = new Finding
        {
            ScannerId = Id,
            Category = FindingCategory.Browser,
            Title = $"{b.Name}: Webseiten duerfen Benachrichtigungen senden ({allowed.Count})",
            Location = profileDir,
            Description = "Erlaubt: " + string.Join(", ", allowed.Take(20)),
            Explanation = "Betrueger bringen Nutzer dazu, auf 'Zulassen' zu klicken, und zeigen dann taeglich gefaelschte Warnungen " +
                          "('Ihr PC ist infiziert', 'Virus gefunden'), die auf Abo-Fallen oder Malware fuehren.",
            Recommendation = $"In {b.Name}: Einstellungen → Datenschutz und Sicherheit → Website-Einstellungen → Benachrichtigungen – unbekannte Seiten entfernen.",
        };
        f.AddIndicator("NOTIFY_SPAM", $"{allowed.Count} unbekannte Seite(n) mit Benachrichtigungsrecht", allowed.Count >= 5 ? 35 : 15);
        ctx.Add(f);
    }

    // ------------------------------------------------------------------
    // Firefox
    // ------------------------------------------------------------------

    private void ScanFirefox(ScanContext ctx, string profileRoot)
    {
        string root = Path.Combine(profileRoot, @"AppData\Roaming\Mozilla\Firefox\Profiles");
        foreach (var profile in SafeDirs(root))
        {
            var ext = LoadJson(Path.Combine(profile, "extensions.json"));
            if (Path_(ext, "addons") is { ValueKind: JsonValueKind.Array } addons)
            {
                foreach (var a in addons.EnumerateArray())
                {
                    string? loc = a.TryGetProperty("location", out var l) ? l.GetString() : null;
                    if (loc is "app-builtin" or "app-system-defaults" or "app-system-addons") continue;
                    if (a.TryGetProperty("type", out var t) && t.GetString() is not "extension") continue;
                    string id = a.TryGetProperty("id", out var i) ? i.GetString() ?? "?" : "?";
                    string name = Path_(a, "defaultLocale", "name")?.GetString() ?? id;
                    int signed = a.TryGetProperty("signedState", out var ss) && ss.TryGetInt32(out var sv) ? sv : 2;

                    var f = new Finding
                    {
                        ScannerId = Id,
                        Category = FindingCategory.Browser,
                        Title = $"Firefox-Erweiterung: {name}",
                        Location = profile,
                        Description = $"Firefox-Erweiterung \"{name}\" ({id}).",
                        Explanation = "Browser-Erweiterungen sehen alles, was Sie auf Webseiten eingeben.",
                        Recommendation = "Pruefen, ob Sie die Erweiterung kennen und noch nutzen.",
                    };
                    if (signed <= 0) f.AddIndicator("FF_UNSIGNED", "Nicht von Mozilla signiert", 40);
                    if (loc is "app-global" or "winreg-app-global" or "winreg-app-user") f.AddIndicator("FF_EXTERNAL", "Von einem anderen Programm installiert", 25);
                    f.Detail("ID", id).Detail("Installationsort", loc);
                    ctx.Add(f);
                }
            }

            try
            {
                string prefs = Path.Combine(profile, "prefs.js");
                if (!File.Exists(prefs)) continue;
                var lines = File.ReadAllLines(prefs).Where(l => l.Contains("network.proxy.autoconfig_url") || l.Contains("network.proxy.http\"")).ToList();
                if (lines.Count == 0) continue;
                var f = new Finding
                {
                    ScannerId = Id,
                    Category = FindingCategory.Browser,
                    Title = "Firefox: Proxy konfiguriert",
                    Location = prefs,
                    Description = string.Join("; ", lines.Select(l => l.Trim())),
                    Explanation = "Ein Proxy kann den gesamten Webverkehr mitlesen und veraendern.",
                    Recommendation = "Firefox → Einstellungen → Verbindungseinstellungen pruefen.",
                };
                f.AddIndicator("FF_PROXY", "Proxy in Firefox gesetzt", 30);
                ctx.Add(f);
            }
            catch { }
        }
    }

    // ------------------------------------------------------------------
    // Browser-Verknuepfungen
    // ------------------------------------------------------------------

    private static readonly HashSet<string> BrowserExes = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "launcher.exe",
    };

    private void ScanBrowserShortcuts(ScanContext ctx, string profileRoot)
    {
        var dirs = new[]
        {
            Path.Combine(profileRoot, "Desktop"),
            Path.Combine(profileRoot, @"AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"),
            Path.Combine(profileRoot, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs"),
        };
        foreach (var dir in dirs.Where(Directory.Exists))
        {
            IEnumerable<string> links;
            try { links = Directory.EnumerateFiles(dir, "*.lnk").ToList(); } catch { continue; }
            foreach (var lnk in links)
            {
                var (target, args) = ShortcutReader.Read(lnk);
                if (target == null || !BrowserExes.Contains(Path.GetFileName(target)) || string.IsNullOrWhiteSpace(args)) continue;
                if (!args.Contains("http", StringComparison.OrdinalIgnoreCase) && !args.Contains("--load-extension", StringComparison.OrdinalIgnoreCase)
                    && !args.Contains("--proxy", StringComparison.OrdinalIgnoreCase)) continue;

                var f = new Finding
                {
                    ScannerId = Id,
                    Category = FindingCategory.Browser,
                    Title = $"Manipulierte Browser-Verknuepfung: {Path.GetFileName(lnk)}",
                    FilePath = lnk,
                    Description = $"Die Verknuepfung startet {Path.GetFileName(target)} mit: {args}",
                    Explanation = "Browser-Hijacker haengen an Verknuepfungen eine Webseite, eine Erweiterung (--load-extension) oder einen Proxy an. " +
                                  "So oeffnet sich bei jedem Start eine Werbe- oder Phishing-Seite.",
                    Recommendation = "Verknuepfung loeschen und neu aus dem Startmenue anheften.",
                };
                f.AddIndicator("LNK_HIJACK", "Browser-Verknuepfung mit angehaengter URL/Erweiterung/Proxy", args.Contains("--load-extension") || args.Contains("--proxy") ? 55 : 40);
                f.Actions.Add(new RemediationAction { Kind = RemediationKind.QuarantineFile, Label = "Verknuepfung in Quarantaene", Target = lnk });
                ctx.Add(f);
            }
        }
    }
}
