using ScanMe.Core.Knowledge;
using ScanMe.Core.Models;
using ScanMe.Core.Trust;

namespace ScanMe.Core.Engine;

/// <summary>
/// Einheitliche Bewertung einer ausfuehrbaren Datei. Wird von Prozess-, Autostart-, Dienst-,
/// Treiber- und Dateiscanner verwendet, damit ueberall dieselben Massstaebe gelten.
/// </summary>
public static class ExecutableAssessor
{
    /// <summary>Originalnamen von Windows-Werkzeugen, die Angreifer gern umbenannt mitbringen.</summary>
    private static readonly HashSet<string> RenameSensitive = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.dll", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe",
        "cscript.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "msbuild.exe", "installutil.exe",
        "psexec.exe", "procdump.exe", "nc.exe", "AutoIt3.exe", "AutoHotkey.exe",
    };

    /// <summary>Windows-eigene Programme, die beliebigen Code ausfuehren koennen ("Living off the Land").</summary>
    public static readonly HashSet<string> LolBins = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "conhost.exe",
        "forfiles.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe", "hh.exe",
        "msxsl.exe", "odbcconf.exe", "pcalua.exe", "scriptrunner.exe", "schtasks.exe", "reg.exe", "curl.exe",
        "bash.exe", "wsl.exe", "msdt.exe", "control.exe", "infdefaultinstall.exe", "mavinject.exe",
    };

    private const char RightToLeftOverride = (char)0x202E;

    private static readonly string[] DocumentExtensions =
        [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip", ".rar", ".rtf", ".csv"];

    public static FileTrustInfo Assess(Finding f, string? path, FileTrustService trust, bool addActions = true)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            f.AddIndicator("NO_PATH", "Kein Dateipfad ermittelbar", 5);
            return new FileTrustInfo { Path = "", Exists = false };
        }

        var info = trust.Get(path);
        f.FilePath ??= info.Path;

        if (!info.Exists)
        {
            f.AddIndicator("FILE_MISSING", "Die referenzierte Datei existiert nicht (verwaister Eintrag oder gelöschte Malware)", 10);
            return info;
        }

        f.Sha256 ??= info.Sha256;
        string fileName = Path.GetFileName(info.Path);
        var loc = LocationClassifier.Classify(info.Path);

        // --- Signatur ---
        switch (info.Signature)
        {
            // Skript-Hosts/LOLBins sind selbst harmlos – entscheidend ist, WAS sie ausfuehren.
            // Ohne diese Ausnahme wuerde die Microsoft-Signatur boesartige Kommandozeilen "neutralisieren".
            case SignatureState.Valid when info.IsWindowsComponent && LolBins.Contains(fileName):
                // Nicht IsProtected: ein boesartiger PowerShell-Prozess darf beendet werden.
                // Die Datei selbst schuetzt AddFileActions (keine Quarantaene fuer Microsoft-Dateien).
                f.AddIndicator("SIG_WINDOWS_HOST", $"Windows-Werkzeug {fileName} (selbst harmlos – bewertet wird der ausgeführte Befehl)", 0);
                break;
            case SignatureState.Valid when info.IsWindowsComponent:
                f.IsProtected = true;
                f.AddIndicator("SIG_WINDOWS", "Verifizierte Windows-Komponente (Microsoft-signiert, Windows-Verzeichnis)", -60);
                break;
            case SignatureState.Valid when info.IsMicrosoftSigned:
                f.AddIndicator("SIG_MICROSOFT", "Gültig von Microsoft signiert", -40);
                break;
            case SignatureState.Valid:
                f.AddIndicator("SIG_VALID", $"Gültig signiert von \"{info.Signer}\"", -25);
                break;
            // Skripte, Verknuepfungen und Abbilder werden praktisch nie signiert – fehlende Signatur ist dort kein Indiz.
            case SignatureState.NotSigned when !IsBinary(fileName):
                f.AddIndicator("SIG_NONE_SCRIPT", "Nicht signiert (bei Skripten/Verknüpfungen üblich)", 0);
                break;
            case SignatureState.NotSigned:
                f.AddIndicator("SIG_NONE", "Datei ist nicht digital signiert", LocationClassifier.IsUserWritable(loc) ? 25 : 15);
                break;
            case SignatureState.Invalid:
                bool tampered = info.SignatureStatusText.Contains("manipuliert");
                f.AddIndicator("SIG_INVALID", $"Ungültige Signatur: {info.SignatureStatusText}", tampered ? 60 : 40);
                break;
        }

        // --- Spielebibliotheken: Spiele sind oft unsigniert und verbinden sich ins Internet – das ist normal ---
        bool game = IsGameLibrary(info.Path);
        if (game && info.Signature != SignatureState.Valid)
            f.AddIndicator("GAME_LIBRARY", "Liegt in einer Spielebibliothek (Steam/Epic/GOG/Xbox …) – Spiele sind häufig nicht signiert", -10);

        // --- Speicherort ---
        int locWeight = game ? 0 : LocationClassifier.Weight(loc);
        if (locWeight > 0 && !info.IsWindowsComponent)
        {
            // Signierte Software in AppData (Discord, Teams, VS Code ...) ist normal – Gewicht reduzieren.
            if (info.Signature == SignatureState.Valid) locWeight /= 3;
            // Skripte/Verknuepfungen liegen oft legitim in Temp/AppData – Ort allein zaehlt dort weniger.
            else if (!IsBinary(fileName)) locWeight /= 2;
            if (locWeight > 0)
                f.AddIndicator("LOC_" + loc.ToString().ToUpperInvariant(), "Datei " + LocationClassifier.Describe(loc), locWeight);
        }

        // --- Herkunft ---
        if (info.FromInternet)
        {
            f.AddIndicator("MOTW", "Aus dem Internet heruntergeladen" + (info.DownloadUrl != null ? $" ({info.DownloadUrl})" : ""),
                info.Signature == SignatureState.Valid ? 0 : 10);
        }

        // --- Doppelte Endung (rechnung.pdf.exe) ---
        string withoutExt = Path.GetFileNameWithoutExtension(fileName);
        if (DocumentExtensions.Any(e => withoutExt.EndsWith(e, StringComparison.OrdinalIgnoreCase)) && PathIsExecutable(fileName))
            f.AddIndicator("DOUBLE_EXT", $"Doppelte Dateiendung \"{fileName}\" – typische Phishing-Tarnung", 50);

        // --- Unicode Right-to-Left-Override im Namen (gnp.exe -> exe.png) ---
        if (fileName.Contains(RightToLeftOverride))
            f.AddIndicator("RTLO", "Dateiname enthält ein unsichtbares Umkehrzeichen (RTLO) zur Tarnung der Endung", 60);

        // --- Systemprozess-Imitation ---
        // Gueltig signierte Programme eines Herstellers tarnen sich nicht mit Tippfehler-Namen (das Zertifikat nennt den Hersteller).
        var lookalike = SystemProcesses.FindLookalike(fileName);
        if (lookalike != null && info.Signature != SignatureState.Valid)
            f.AddIndicator("LOOKALIKE", $"Name ahmt den Windows-Prozess \"{lookalike}\" nach", 50);

        var profile = SystemProcesses.Get(fileName);
        if (profile != null && profile.ExpectedDirs.Length > 0 && !info.IsWindowsComponent
            && !profile.ExpectedDirs.Any(d => string.Equals(Path.GetDirectoryName(info.Path), d, StringComparison.OrdinalIgnoreCase)))
        {
            f.AddIndicator("MASQUERADE", $"Trägt den Namen eines Windows-Systemprozesses, liegt aber nicht in {string.Join(" / ", profile.ExpectedDirs)}", 70);
        }

        // --- Umbenanntes Systemwerkzeug ---
        if (info.OriginalFilename != null)
        {
            string orig = info.OriginalFilename.Replace(".mui", "", StringComparison.OrdinalIgnoreCase);
            if (RenameSensitive.Contains(orig) && !orig.Equals(fileName, StringComparison.OrdinalIgnoreCase))
                f.AddIndicator("RENAMED_TOOL", $"Umbenanntes Werkzeug: eigentlich \"{orig}\", hier als \"{fileName}\"", 45);
        }

        // --- Gefaelschte Herstellerangaben: behauptet Microsoft, ist aber nicht von Microsoft signiert ---
        bool claimsMicrosoft = (info.CompanyName?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ?? false)
                               || (info.ProductName?.Contains("Microsoft Windows", StringComparison.OrdinalIgnoreCase) ?? false);
        if (claimsMicrosoft && !info.IsMicrosoftSigned && info.Signature != SignatureState.Valid)
            f.AddIndicator("FAKE_MICROSOFT", $"Gibt sich als Microsoft aus (\"{info.CompanyName ?? info.ProductName}\"), ist aber nicht von Microsoft signiert", 45);

        // --- Fehlende Metadaten ---
        if (info.Signature != SignatureState.Valid && info.CompanyName == null && info.FileDescription == null && fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            f.AddIndicator("NO_METADATA", "Keine Herstellerangaben in der Datei", 10);

        // --- Frisch erstellt ---
        if (info.Signature != SignatureState.Valid && IsBinary(fileName) && info.Created is { } created && (DateTime.Now - created).TotalDays < 7)
            f.AddIndicator("RECENT", $"Erst kürzlich erstellt ({created:g})", 8);

        // --- Bekannte Werkzeuge ---
        var tool = KnownTools.FindByProcessName(fileName);
        if (tool != null)
        {
            int w = tool.Kind switch
            {
                KnownTools.ToolKind.HackTool => 60,
                KnownTools.ToolKind.Miner => 55,
                KnownTools.ToolKind.Tunnel => 35,
                _ => 30,
            };
            f.AddIndicator("TOOL_" + tool.Kind.ToString().ToUpperInvariant(), $"{KnownTools.KindText(tool.Kind)}: {tool.Name}. {tool.Note}", w);
        }

        AddDetails(f, info);
        if (addActions) AddFileActions(f, info);
        return info;
    }

    public static void AddDetails(Finding f, FileTrustInfo info)
    {
        f.Detail("Datei", info.Path)
         .Detail("Signatur", info.SignatureStatusText)
         .Detail("Signiert von", info.Signer)
         .Detail("Hersteller", info.CompanyName)
         .Detail("Produkt", info.ProductName)
         .Detail("Beschreibung", info.FileDescription)
         .Detail("Version", info.FileVersion)
         .Detail("Originalname", info.OriginalFilename)
         .Detail("SHA256", info.Sha256)
         .Detail("Größe", info.Exists ? Util.TextUtil.FormatBytes(info.Size) : null)
         .Detail("Erstellt", info.Created?.ToString("g"))
         .Detail("Geändert", info.Modified?.ToString("g"))
         .Detail("Download-Quelle", info.DownloadUrl)
         .Detail("Download-Referrer", info.DownloadReferrer);
    }

    public static void AddFileActions(Finding f, FileTrustInfo info)
    {
        if (!info.Exists) return;
        if (!f.Actions.Any(a => a.Kind == RemediationKind.OpenLocation))
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.OpenLocation, Label = "Speicherort öffnen", Target = info.Path, RequiresConfirmation = false });
        if (info.Sha256 != null && !f.Actions.Any(a => a.Kind == RemediationKind.LookupOnline))
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.LookupOnline, Label = "Auf VirusTotal prüfen", Target = info.Sha256, RequiresConfirmation = false });
        if (!f.Actions.Any(a => a.Kind == RemediationKind.DefenderScanFile))
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.DefenderScanFile, Label = "Mit Defender scannen", Target = info.Path, RequiresConfirmation = false });
        if (!info.IsWindowsComponent && !info.IsMicrosoftSigned && !f.Actions.Any(a => a.Kind == RemediationKind.QuarantineFile))
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.QuarantineFile, Label = "In Quarantäne verschieben", Target = info.Path });
    }

    private static readonly string[] GameLibraryMarkers =
    [
        @"\steamapps\common\", @"\Epic Games\", @"\GOG Galaxy\Games\", @"\GOG Games\", @"\XboxGames\", @"\Riot Games\",
        @"\Ubisoft Game Launcher\games\", @"\EA Games\", @"\Battle.net\", @"\Blizzard Entertainment\", @"\Rockstar Games\",
    ];

    public static bool IsGameLibrary(string? path) =>
        path != null && GameLibraryMarkers.Any(m => path.Contains(m, StringComparison.OrdinalIgnoreCase));

    /// <summary>Programmdateien, bei denen eine Signatur zu erwarten ist.</summary>
    public static bool IsBinary(string fileName) =>
        Path.GetExtension(fileName).ToLowerInvariant() is ".exe" or ".dll" or ".sys" or ".scr" or ".com" or ".cpl" or ".ocx" or ".msi" or ".pif" or ".drv" or ".efi";

    private static bool PathIsExecutable(string fileName) =>
        Util.PathUtil.LooksExecutable(fileName) && !fileName.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase);
}
