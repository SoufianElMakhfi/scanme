using System.Text.RegularExpressions;
using ScanMe.Core.Engine;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Models;
using ScanMe.Core.Native;
using ScanMe.Core.Trust;
using ScanMe.Core.Util;

namespace ScanMe.Core.Scanners;

/// <summary>
/// Durchsucht die typischen Ablageorte von Malware und Phishing-Anhaengen: versteckte Programme,
/// Doppelendungen, Skripte, boesartige Verknuepfungen, ADS, Ransomware-Spuren.
/// </summary>
public sealed partial class FileSystemScanner : IScanner
{
    public string Id => "filesystem";
    public string Name => "Dateisystem & Phishing-Spuren";
    public string Description => "Versteckte/verdaechtige Dateien in Downloads, AppData, Temp, Public, ProgramData und Papierkorb.";
    public bool InQuickScan => false;

    private const int MaxFiles = 250_000;

    private static readonly HashSet<string> PeExt = new(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".scr", ".com", ".cpl", ".ocx", ".pif", ".msi" };
    private static readonly HashSet<string> ScriptExt = new(StringComparer.OrdinalIgnoreCase) { ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".bat", ".cmd" };
    private static readonly HashSet<string> ContainerExt = new(StringComparer.OrdinalIgnoreCase) { ".iso", ".img", ".vhd", ".vhdx" };
    private static readonly HashSet<string> MacroExt = new(StringComparer.OrdinalIgnoreCase) { ".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".xltm", ".ppam" };

    private static readonly HashSet<string> RansomExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".locked", ".encrypted", ".crypted", ".crypt", ".enc", ".lockbit", ".ryk", ".conti", ".wncry", ".wnry", ".cerber", ".locky",
        ".zepto", ".odin", ".thor", ".aesir", ".zzzzz", ".micro", ".vvv", ".ccc", ".ecc", ".exx", ".ezz", ".xxx", ".ttt", ".mp3#ransom",
        ".petya", ".gandcrab", ".krab", ".phobos", ".dharma", ".makop", ".blackcat", ".hive", ".royal", ".akira", ".play", ".basta",
    };

    private static readonly HashSet<string> BenignStreams = new(StringComparer.OrdinalIgnoreCase)
    {
        "Zone.Identifier", "SmartScreen", "ms-properties", "OECustomProperty", "encryptable", "favicon", "AFP_AfpInfo", "AFP_Resource",
        "com.dropbox.attrs", "com.dropbox.attributes", "Win32App_1", "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}", "\u0005SummaryInformation",
        "\u0005DocumentSummaryInformation", "KAVICHS", "TaskbarPin", "WofCompressedData",
    };

    /// <summary>Unterordner, die gross, harmlos und sehr zeitaufwendig sind.</summary>
    private static readonly HashSet<string> SkipDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "node_modules", ".git", "Packages", "Package Cache", "WinSxS", "Cache", "Code Cache", "GPUCache", "Service Worker", "IndexedDB",
        "CacheStorage", "npm-cache", "pip", "NuGet", ".nuget", "JetBrains", "Docker", "wsl", "Steam", "SteamLibrary", "Epic Games",
        "Riot Games", "Battle.net", "Microsoft SDKs", "Windows Kits", "Unity", "Adobe", "Mozilla", "Google", "BraveSoftware",
        "Microsoft\\Edge", "CrashDumps", "D3DSCache", "NVIDIA", "NVIDIA Corporation", "AMD", "Intel", "assembly", "Microsoft.NET",
        "dotnet", "Python", "conda", "anaconda3", "miniconda3", ".vscode", ".cursor", "Postman", "go", "cargo", ".rustup", "gradle",
        // Grosse Microsoft-Caches unter AppData\Local\Microsoft (der Rest wird geprueft – Malware tarnt sich dort gern)
        "Edge", "OneDrive", "Teams", "Office", "Outlook", "INetCache", "WebCache", "Explorer", "Caches", "Notifications",
        "Feeds Cache", "PlayReady", "Terminal Server Client", "WindowsApps", "Media Player",
    };

    [GeneratedRegex(@"(readme|read_me|how_to|howto|decrypt|restore|recover|instruction|!!!|_help_|help_decrypt|unlock).*\.(txt|html?|hta|rtf)$", RegexOptions.IgnoreCase)]
    private static partial Regex RansomNoteName();

    [GeneratedRegex(@"^[a-z0-9]{6,20}$", RegexOptions.IgnoreCase)]
    private static partial Regex AlnumName();

    private int _filesSeen;
    private readonly Dictionary<string, int> _ransomExtCount = new(StringComparer.OrdinalIgnoreCase);

    public Task ScanAsync(ScanContext ctx)
    {
        _filesSeen = 0;
        _ransomExtCount.Clear();

        foreach (var (dir, depth) in Targets(ctx))
        {
            ctx.ThrowIfCancelled();
            if (!Directory.Exists(dir)) continue;
            ctx.Status($"Durchsuche {dir} …");
            Walk(ctx, dir, depth);
            if (_filesSeen >= MaxFiles)
            {
                ctx.Note($"Dateilimit von {MaxFiles} erreicht – nicht alle Ordner wurden vollstaendig geprueft.");
                break;
            }
        }

        ReportRansomExtensions(ctx);
        ctx.Note($"{_filesSeen:N0} Dateien geprueft.");
        return Task.CompletedTask;
    }

    private static IEnumerable<(string Dir, int Depth)> Targets(ScanContext ctx)
    {
        foreach (var p in SystemEnv.UserProfiles())
        {
            if (Path.GetFileName(p).Equals("Public", StringComparison.OrdinalIgnoreCase))
            {
                yield return (p, 4);
                continue;
            }
            yield return (Path.Combine(p, "Downloads"), 3);
            yield return (Path.Combine(p, "Desktop"), 2);
            yield return (Path.Combine(p, "OneDrive", "Desktop"), 2);
            yield return (Path.Combine(p, "Documents"), 1);
            yield return (Path.Combine(p, @"AppData\Local\Temp"), 4);
            yield return (Path.Combine(p, @"AppData\Roaming"), 4);
            yield return (Path.Combine(p, @"AppData\Local"), 3);
            yield return (Path.Combine(p, @"AppData\LocalLow"), 3);
            yield return (Path.Combine(p, @"AppData\Local\Microsoft\Windows\INetCache\IE"), 2);
            yield return (Path.Combine(p, @"AppData\Local\Microsoft\Windows\INetCache\Content.Outlook"), 3);
            yield return (Path.Combine(p, @"AppData\Local\Microsoft\Olk\Attachments"), 3);
        }
        yield return (PathUtil.ProgramData, 3);
        yield return (Path.Combine(PathUtil.WindowsDir, "Temp"), 3);
        yield return (Path.Combine(PathUtil.WindowsDir, "Tasks"), 1);
        yield return (Path.Combine(PathUtil.System32, "Tasks"), 0); // nur Nicht-XML-Dateien sind hier verdaechtig
        yield return (@"C:\PerfLogs", 3);
        yield return (@"C:\", 0);
        yield return (@"C:\$Recycle.Bin", 3);
        foreach (var extra in ctx.Options.ExtraPaths) yield return (extra, 6);
    }

    private void Walk(ScanContext ctx, string root, int maxDepth)
    {
        var stack = new Stack<(string Dir, int Depth, bool HiddenParent)>();
        stack.Push((root, 0, false));
        while (stack.Count > 0 && _filesSeen < MaxFiles)
        {
            ctx.ThrowIfCancelled();
            var (dir, depth, hiddenParent) = stack.Pop();

            IEnumerable<FileSystemInfo> entries;
            try { entries = new DirectoryInfo(dir).EnumerateFileSystemInfos().ToList(); }
            catch { continue; }

            foreach (var e in entries)
            {
                if (e is DirectoryInfo d)
                {
                    if (depth >= maxDepth) continue;
                    if ((d.Attributes & FileAttributes.ReparsePoint) != 0) continue; // Junctions ("Application Data") nicht folgen
                    if (SkipDirs.Contains(d.Name)) continue;
                    if (d.FullName.Equals(Path.Combine(PathUtil.ProgramData, "Microsoft"), StringComparison.OrdinalIgnoreCase)) continue;
                    // Temp und Roaming werden separat mit eigener Tiefe gescannt
                    if (dir.EndsWith(@"AppData\Local", StringComparison.OrdinalIgnoreCase) && d.Name is "Temp" or "Programs") continue;
                    bool hidden = (d.Attributes & FileAttributes.Hidden) != 0;
                    stack.Push((d.FullName, depth + 1, hiddenParent || hidden));
                }
                else if (e is FileInfo fi)
                {
                    _filesSeen++;
                    try { AnalyzeFile(ctx, fi, hiddenParent, depth); }
                    catch { /* einzelne Datei nicht lesbar */ }
                }
            }
        }
    }

    // ------------------------------------------------------------------

    private void AnalyzeFile(ScanContext ctx, FileInfo fi, bool hiddenParent, int depth)
    {
        string ext = fi.Extension;
        string name = fi.Name;

        // $I-Dateien im Papierkorb sind nur Metadaten (Originalname/-pfad), keine Programme
        if (name.StartsWith("$I", StringComparison.Ordinal) && fi.FullName.Contains(@"\$Recycle.Bin\", StringComparison.OrdinalIgnoreCase)) return;

        if (RansomExt.Contains(ext))
            _ransomExtCount[ext] = _ransomExtCount.GetValueOrDefault(ext) + 1;

        if (RansomNoteName().IsMatch(name) && fi.Length < 200_000)
            CheckRansomNote(ctx, fi);

        bool isPe = PeExt.Contains(ext);
        bool isScript = ScriptExt.Contains(ext);
        bool isLnk = ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase);
        bool isContainer = ContainerExt.Contains(ext);
        bool isMacro = MacroExt.Contains(ext) || ext.Equals(".one", StringComparison.OrdinalIgnoreCase);

        CheckAlternateStreams(ctx, fi);

        if (!isPe && !isScript && !isLnk && !isContainer && !isMacro) return;

        var loc = LocationClassifier.Classify(fi.FullName);
        bool hidden = (fi.Attributes & FileAttributes.Hidden) != 0;
        bool system = (fi.Attributes & FileAttributes.System) != 0;
        bool hotLocation = loc is LocationKind.Temp or LocationKind.Public or LocationKind.RecycleBin;

        // DLLs & Co. in Programmordnern gibt es zu Tausenden – nur bei konkretem Anlass voll pruefen.
        if (isPe && !IsExeLike(ext) && !(hidden || hiddenParent || hotLocation || depth == 0 || LooksRandom(fi.Directory?.Name ?? "")))
            return;

        // Skripte nur dort bewerten, wo Phishing-Anhaenge und Dropper landen – nicht in Projekt- und App-Ordnern.
        if (isScript && !(hidden || hiddenParent || hotLocation
                          || (loc == LocationKind.Downloads && depth <= 1)
                          || depth == 0))
            return;
        // Grosse Skripte sind gebuendelter App-Code; Phishing-Dropper sind klein.
        if (isScript && fi.Length > 1024 * 1024 && !hidden) return;
        // JavaScript in Node-Projekten ist Entwicklercode
        if (isScript && ext.Equals(".js", StringComparison.OrdinalIgnoreCase) && fi.DirectoryName != null
            && File.Exists(Path.Combine(fi.DirectoryName, "package.json")))
            return;

        var f = new Finding
        {
            ScannerId = Id,
            Category = FindingCategory.FileSystem,
            Title = $"Verdaechtige Datei: {name}",
            FilePath = fi.FullName,
            Location = fi.DirectoryName,
        };

        if (hidden && (isPe || isScript))
            f.AddIndicator("FILE_HIDDEN", system ? "Datei ist als versteckte Systemdatei getarnt" : "Datei ist versteckt", system ? 35 : 25);
        // In ProgramData sind versteckte Herstellerordner normal
        if (hiddenParent && (isPe || isScript) && loc != LocationKind.ProgramData)
            f.AddIndicator("DIR_HIDDEN", "Liegt in einem versteckten Ordner", 15);

        if (isPe) AnalyzePe(ctx, f, fi, loc);
        else if (isScript) AnalyzeScript(ctx, f, fi, loc);
        else if (isLnk) AnalyzeLnk(f, fi, loc);
        else if (isContainer || isMacro) AnalyzePhishingContainer(ctx, f, fi, isContainer);

        int score = f.Indicators.Sum(i => i.Weight);
        if (score < 30) return;

        // Nur "schwache" Indikatoren (unsigniert + Ort) -> hoechstens Niedrig, um Alarmmuedigkeit zu vermeiden
        var weak = new HashSet<string> { "SIG_NONE", "NO_METADATA", "RECENT", "MOTW", "SCRIPT_LOCATION" };
        if (f.Indicators.Where(i => i.Weight > 0).All(i => weak.Contains(i.Code) || i.Code.StartsWith("LOC_")))
            f.AddIndicator("WEAK_ONLY", "Nur allgemeine Merkmale, keine konkreten Malware-Hinweise", -Math.Max(0, score - 10));

        f.Description = $"{fi.FullName} ({TextUtil.FormatBytes(fi.Length)}, erstellt {fi.CreationTime:g})" +
                        (f.Details.TryGetValue("Download-Quelle", out var url) ? $" – heruntergeladen von {url}" : "");
        f.Explanation ??= "";
        if (f.Explanation.Length == 0)
            f.Explanation = "Die Datei liegt an einem Ort, den Malware und Phishing-Anhaenge typischerweise nutzen, und weist die aufgefuehrten Merkmale auf.";
        f.Recommendation = score >= 60
            ? "Datei nicht oeffnen. In Quarantaene verschieben und auf VirusTotal pruefen. Wenn sie bereits geoeffnet wurde: vollstaendigen Defender-Scan ausfuehren und Passwoerter aendern."
            : "Wenn Sie die Datei nicht kennen oder nicht bewusst heruntergeladen haben: nicht oeffnen, auf VirusTotal pruefen und ggf. loeschen bzw. in Quarantaene verschieben.";
        if (!f.Actions.Any(a => a.Kind == RemediationKind.QuarantineFile))
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.QuarantineFile, Label = "In Quarantaene verschieben", Target = fi.FullName });
        if (!f.Actions.Any(a => a.Kind == RemediationKind.OpenLocation))
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.OpenLocation, Label = "Speicherort oeffnen", Target = fi.FullName, RequiresConfirmation = false });
        ctx.Add(f);
    }

    private static void AnalyzePe(ScanContext ctx, Finding f, FileInfo fi, LocationKind loc)
    {
        var info = ExecutableAssessor.Assess(f, fi.FullName, ctx.Trust);
        if (info.IsWindowsComponent) return;

        string? parent = fi.Directory?.Name;
        string? grand = fi.Directory?.Parent?.Name;
        if (grand is "AppData" && parent is "Roaming" or "Local" or "LocalLow")
            f.AddIndicator("APPDATA_ROOT", "Programm liegt direkt im AppData-Stammordner (kein eigener Programmordner)", 20);
        if (fi.DirectoryName?.Equals(@"C:\", StringComparison.OrdinalIgnoreCase) == true)
            f.AddIndicator("DRIVE_ROOT", "Programm liegt direkt im Laufwerksstamm C:\\", 15);
        if (fi.DirectoryName?.StartsWith(Path.Combine(PathUtil.System32, "Tasks"), StringComparison.OrdinalIgnoreCase) == true
            || fi.DirectoryName?.StartsWith(Path.Combine(PathUtil.WindowsDir, "Tasks"), StringComparison.OrdinalIgnoreCase) == true)
            f.AddIndicator("IN_TASKS_DIR", "Programmdatei im Aufgabenordner von Windows (dort gehoeren nur Aufgabendefinitionen hin)", 45);
        if (parent != null && LocationClassifier.IsUserWritable(loc) && LooksRandom(parent))
            f.AddIndicator("RANDOM_DIR", $"Ordnername \"{parent}\" wirkt zufaellig generiert", 10);

        if (info.Signature != SignatureState.Valid)
            StaticAnalyzer.Analyze(f, fi.FullName);
    }

    private static void AnalyzeScript(ScanContext ctx, Finding f, FileInfo fi, LocationKind loc)
    {
        string ext = fi.Extension.ToLowerInvariant();
        int locWeight = LocationClassifier.Weight(loc);
        if (locWeight > 0) f.AddIndicator("SCRIPT_LOCATION", "Skript " + LocationClassifier.Describe(loc), Math.Min(locWeight, 20));

        int extWeight = ext switch
        {
            ".hta" or ".vbe" or ".jse" or ".wsf" or ".wsh" => 25,
            ".js" or ".vbs" when loc is LocationKind.Downloads or LocationKind.Temp or LocationKind.Desktop => 20,
            _ => 0,
        };
        if (extWeight > 0) f.AddIndicator("SCRIPT_TYPE", $"{ext}-Skript – beliebtes Format fuer Phishing-Anhaenge (wird per Doppelklick sofort ausgefuehrt)", extWeight);

        var motw = ZoneIdentifier.Read(fi.FullName);
        if (motw.ZoneId >= 3)
        {
            f.AddIndicator("SCRIPT_DOWNLOADED", "Skript wurde aus dem Internet heruntergeladen", 15);
            f.Detail("Download-Quelle", motw.HostUrl).Detail("Download-Referrer", motw.ReferrerUrl);
        }

        if (fi.Length <= 2 * 1024 * 1024)
        {
            string content;
            try { content = File.ReadAllText(fi.FullName); }
            catch { return; }
            // Harte Indikatoren zaehlen voll; "weiche" (Downloads, Policy-Bypass ...) sind in Admin-Skripten
            // alltaeglich und werden gemeinsam gedeckelt.
            var rules = CommandLineRules.Match(content).ToList();
            foreach (var rule in rules.Where(r => HardScriptRules.Contains(r.Id)))
                f.AddIndicator("SCRIPT_" + rule.Id, "Im Skript: " + rule.Text, rule.Weight);
            var soft = rules.Where(r => !HardScriptRules.Contains(r.Id)).ToList();
            if (soft.Count > 0)
                f.AddIndicator("SCRIPT_CONTENT", "Im Skript: " + string.Join("; ", soft.Select(r => r.Text)), Math.Min(soft.Sum(r => r.Weight), 25));
            StaticAnalyzer.Analyze(f, fi.FullName);
            f.Detail("Skriptauszug", TextUtil.Truncate(content.Replace("\r", "").Replace("\n", " ⏎ "), 400));
        }
        f.Detail("Erstellt", fi.CreationTime.ToString("g")).Detail("SHA256", FileTrustService.TryHash(fi.FullName));
        f.Sha256 = f.Details.GetValueOrDefault("SHA256");
        if (f.Sha256 != null)
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.LookupOnline, Label = "Auf VirusTotal pruefen", Target = f.Sha256, RequiresConfirmation = false });
    }

    private static void AnalyzeLnk(Finding f, FileInfo fi, LocationKind loc)
    {
        // Startmenue-Verknuepfungen (Roaming) sind normal; Autostart-Ordner prueft der Persistenz-Scanner.
        if (loc is not (LocationKind.Downloads or LocationKind.Desktop or LocationKind.Temp or LocationKind.Public))
            return;
        var (target, args) = ShortcutReader.Read(fi.FullName);
        if (target == null) return;
        string targetName = Path.GetFileName(target);
        f.Detail("Ziel", target).Detail("Argumente", args);

        bool benignHost = targetName.Equals("control.exe", StringComparison.OrdinalIgnoreCase) || targetName.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);
        if (ExecutableAssessor.LolBins.Contains(targetName) && !benignHost && !string.IsNullOrWhiteSpace(args))
        {
            f.AddIndicator("LNK_LOLBIN", $"Verknuepfung startet {targetName} mit Parametern – klassische LNK-Phishing-Technik", 45);
            foreach (var rule in CommandLineRules.Match(args))
                f.AddIndicator("LNK_" + rule.Id, rule.Text, rule.Weight);
            f.Explanation = "Angreifer verschicken Verknuepfungen (.lnk), die wie Dokumente aussehen, beim Oeffnen aber PowerShell oder cmd mit Schadcode starten.";
        }
        if (args?.Length > 300)
            f.AddIndicator("LNK_LONG_ARGS", "Ungewoehnlich lange Parameter in der Verknuepfung", 20);
    }

    private static void AnalyzePhishingContainer(ScanContext ctx, Finding f, FileInfo fi, bool isContainer)
    {
        var motw = ZoneIdentifier.Read(fi.FullName);
        bool fromInternet = motw.ZoneId >= 3;
        bool inMail = fi.FullName.Contains("Content.Outlook", StringComparison.OrdinalIgnoreCase) || fi.FullName.Contains(@"\Olk\", StringComparison.OrdinalIgnoreCase);
        if (!fromInternet && !inMail) return;

        f.Detail("Download-Quelle", motw.HostUrl).Detail("Download-Referrer", motw.ReferrerUrl);
        if (isContainer)
        {
            f.AddIndicator("CONTAINER", $"{fi.Extension}-Abbilddatei aus dem Internet – wird in Phishing-Kampagnen genutzt, um Windows-Schutzmechanismen (Mark of the Web) zu umgehen", fi.Length > 500L * 1024 * 1024 ? 5 : 35);
            f.Explanation = "Disk-Images (ISO/IMG/VHD) werden beim Doppelklick als Laufwerk eingebunden. Die darin enthaltenen Dateien verlieren dabei die Internet-Markierung – SmartScreen und Office-Makroschutz greifen nicht mehr.";
        }
        else
        {
            f.AddIndicator("MACRO_DOC", $"Dokument mit Makros/eingebetteten Inhalten ({fi.Extension}) aus dem Internet/E-Mail", 30);
            f.Explanation = "Makro-Dokumente und OneNote-Dateien sind klassische Phishing-Anhaenge: Ein Klick auf 'Inhalt aktivieren' fuehrt Schadcode aus.";
        }
        f.Sha256 = FileTrustService.TryHash(fi.FullName);
        f.Detail("SHA256", f.Sha256);
        if (f.Sha256 != null)
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.LookupOnline, Label = "Auf VirusTotal pruefen", Target = f.Sha256, RequiresConfirmation = false });
    }

    // ------------------------------------------------------------------

    private void CheckAlternateStreams(ScanContext ctx, FileInfo fi)
    {
        var hFind = NativeMethods.FindFirstStreamW(fi.FullName, 0, out var data, 0);
        if (hFind == IntPtr.Zero || hFind == new IntPtr(-1)) return;
        try
        {
            do
            {
                // Format ":name:$DATA"; der Hauptstrom heisst "::$DATA"
                string raw = data.cStreamName;
                if (raw == "::$DATA") continue;
                string stream = raw.TrimStart(':');
                int colon = stream.IndexOf(':');
                if (colon >= 0) stream = stream[..colon];
                if (BenignStreams.Contains(stream) || data.StreamSize == 0) continue;

                var f = new Finding
                {
                    ScannerId = Id,
                    Category = FindingCategory.FileSystem,
                    Title = $"Versteckter Datenstrom: {fi.Name}:{stream}",
                    FilePath = fi.FullName,
                    Location = fi.DirectoryName,
                    Description = $"An die Datei {fi.FullName} ist ein versteckter NTFS-Datenstrom \"{stream}\" ({TextUtil.FormatBytes(data.StreamSize)}) angehaengt.",
                    Explanation = "Alternative Datenstroeme (ADS) sind im Explorer unsichtbar. Malware versteckt darin Programme oder Konfigurationsdaten.",
                    Recommendation = $"Inhalt pruefen: Get-Content -Path \"{fi.FullName}\" -Stream \"{stream}\". Unbekannte Datenstroeme mit Remove-Item -Stream entfernen.",
                };
                // Kleine Stroeme setzen auch Backup-/AV-Programme zur Dateimarkierung – erst gross oder mit Programm relevant.
                bool big = data.StreamSize > 64 * 1024;
                f.AddIndicator("ADS", "Versteckter alternativer Datenstrom", big ? 40 : 5);
                try
                {
                    using var fs = new FileStream($"{fi.FullName}:{stream}", FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var head = new byte[2];
                    if (fs.Read(head, 0, 2) == 2 && head[0] == 'M' && head[1] == 'Z')
                        f.AddIndicator("ADS_PE", "Der versteckte Datenstrom enthaelt ein ausfuehrbares Programm!", 50);
                }
                catch { }
                ctx.Add(f);
            }
            while (NativeMethods.FindNextStreamW(hFind, out data));
        }
        finally
        {
            NativeMethods.FindClose(hFind);
        }
    }

    private void CheckRansomNote(ScanContext ctx, FileInfo fi)
    {
        string content;
        try { content = File.ReadAllText(fi.FullName); }
        catch { return; }
        string[] markers = ["encrypted", "verschluesselt", "verschlüsselt", "bitcoin", "decrypt", ".onion", "tor browser", "private key", "ransom", "monero"];
        int hits = markers.Count(m => content.Contains(m, StringComparison.OrdinalIgnoreCase));
        if (hits < 3) return;

        var f = new Finding
        {
            ScannerId = Id,
            Category = FindingCategory.Malware,
            Title = $"Moegliche Loesegeldforderung: {fi.Name}",
            FilePath = fi.FullName,
            Location = fi.DirectoryName,
            Description = $"Die Datei {fi.FullName} (erstellt {fi.CreationTime:g}) enthaelt typische Formulierungen einer Ransomware-Erpressung.",
            Explanation = "Erpressungstrojaner hinterlegen solche Notizen in jedem verschluesselten Ordner.",
            Recommendation = "PC sofort vom Netzwerk trennen, nicht bezahlen, keine Dateien loeschen. Auf nomoreransom.org pruefen, ob es ein Entschluesselungstool gibt, und Fachleute bzw. die Polizei (Cybercrime) einschalten.",
        };
        f.AddIndicator("RANSOM_NOTE", "Typische Inhalte einer Ransomware-Notiz", 60 + hits * 5);
        f.Detail("Auszug", TextUtil.Truncate(content, 400));
        ctx.Add(f);
    }

    private void ReportRansomExtensions(ScanContext ctx)
    {
        foreach (var (ext, count) in _ransomExtCount.Where(kv => kv.Value >= 20))
        {
            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Malware,
                Title = $"Viele Dateien mit Ransomware-Endung {ext}",
                Description = $"{count} Dateien tragen die Endung {ext}.",
                Explanation = "Erpressungstrojaner haengen verschluesselten Dateien eine eigene Endung an.",
                Recommendation = "Pruefen, ob sich betroffene Dateien noch oeffnen lassen. Falls nicht: PC vom Netz trennen und Fachleute hinzuziehen.",
            };
            f.AddIndicator("RANSOM_EXT", $"{count} Dateien mit typischer Ransomware-Endung", count >= 100 ? 85 : 60);
            ctx.Add(f);
        }
    }

    private static readonly HashSet<string> HardScriptRules = new(StringComparer.Ordinal)
    {
        "PS_ENCODED", "PS_AMSI", "PS_DEFENDER_OFF", "PS_REFLECTION", "SHADOW_DELETE", "BCDEDIT_RECOVERY", "LOG_CLEAR",
        "LSASS_DUMP", "SAM_DUMP", "STICKY_KEYS", "REGSVR_SCROBJ", "MSHTA_URL", "RUNDLL_JS", "CERTUTIL_DL", "NET_ADMIN_ADD", "WMIC_XSL",
    };

    private static bool IsExeLike(string ext) => ext.ToLowerInvariant() is ".exe" or ".scr" or ".com" or ".pif" or ".msi" or ".cpl";

    private static bool LooksRandom(string name)
    {
        // Nur reine Buchstabenfolgen fast ohne Vokale ("Xkqzfvbt") – Namen mit Ziffern (Versionen) sind meist legitim.
        if (!AlnumName().IsMatch(name) || name.Length < 7 || name.Any(char.IsDigit)) return false;
        int vowels = name.Count(c => "aeiouyAEIOUY".Contains(c));
        return (double)vowels / name.Length < 0.12;
    }
}
