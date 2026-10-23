using System.Management;
using ScanMe.Core.Engine;
using ScanMe.Core.Models;
using ScanMe.Core.Util;

namespace ScanMe.Core.Scanners;

/// <summary>
/// Prueft sicherheitsrelevante Windows-Einstellungen. Angreifer schwaechen nach dem Eindringen
/// gezielt Defender, Firewall, UAC & Co. – solche Abweichungen sind daher doppelt wichtig.
/// </summary>
public sealed class SecurityConfigScanner : IScanner
{
    public string Id => "security";
    public string Name => "Sicherheitseinstellungen";
    public string Description => "Defender, Ausnahmen, Firewall, UAC, Updates, Passwortschutz, RDP, SMBv1 und mehr.";
    public bool InQuickScan => true;

    public Task ScanAsync(ScanContext ctx)
    {
        ctx.Status("Microsoft Defender …");
        ScanDefender(ctx);
        ScanDefenderExclusions(ctx);
        ctx.Status("Firewall, UAC, SmartScreen …");
        ScanFirewall(ctx);
        ScanUac(ctx);
        ScanSmartScreen(ctx);
        ctx.Status("Anmeldeschutz …");
        ScanCredentialProtection(ctx);
        ScanRemoteAccess(ctx);
        ctx.Status("Updates & Systemstatus …");
        ScanUpdates(ctx);
        ScanPlatform(ctx);
        return Task.CompletedTask;
    }

    private Finding Add(ScanContext ctx, string title, int weight, string description, string explanation, string recommendation, string? location = null)
    {
        var f = new Finding
        {
            ScannerId = Id,
            Category = FindingCategory.SecurityConfig,
            Title = title,
            Description = description,
            Explanation = explanation,
            Recommendation = recommendation,
            Location = location,
        };
        f.AddIndicator("CONFIG", title, weight);
        ctx.Add(f);
        return f;
    }

    // ------------------------------------------------------------------
    // Defender
    // ------------------------------------------------------------------

    private void ScanDefender(ScanContext ctx)
    {
        const string policy = @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender";
        if (RegistryUtil.GetInt(policy, "DisableAntiSpyware") == 1 || RegistryUtil.GetInt(policy, "DisableAntiVirus") == 1)
            Add(ctx, "Microsoft Defender per Richtlinie abgeschaltet", 70,
                "In der Registry ist eine Richtlinie gesetzt, die Microsoft Defender deaktiviert.",
                "Malware setzt diese Richtlinie haeufig, um den Virenschutz auszuschalten. Ohne anderen Virenschutz ist der PC ungeschuetzt.",
                "Wenn kein anderer Virenschutz installiert ist: Wert 'DisableAntiSpyware' entfernen und neu starten.", policy)
                .Actions.Add(new RemediationAction { Kind = RemediationKind.DeleteRegistryValue, Label = "Richtlinie entfernen (mit Sicherung)", Target = policy, Argument = "DisableAntiSpyware" });

        const string rtp = policy + @"\Real-Time Protection";
        if (RegistryUtil.GetInt(rtp, "DisableRealtimeMonitoring") == 1 || RegistryUtil.GetInt(rtp, "DisableBehaviorMonitoring") == 1)
            Add(ctx, "Defender-Echtzeitschutz per Richtlinie deaktiviert", 60,
                "Eine Richtlinie schaltet den Echtzeit- bzw. Verhaltensschutz ab.",
                "Ohne Echtzeitschutz werden Schadprogramme beim Start nicht blockiert. Typische Massnahme von Angreifern.",
                "Richtlinie entfernen, sofern sie nicht von Ihrer IT gesetzt wurde.", rtp);

        if (RegistryUtil.GetInt(@"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend", "Start") == 4)
            Add(ctx, "Defender-Dienst deaktiviert", 50,
                "Der Dienst 'WinDefend' ist deaktiviert.",
                "Das ist nur normal, wenn ein anderes Antivirenprogramm aktiv ist.",
                "Pruefen, ob ein anderer Virenschutz laeuft. Falls nicht: Defender reaktivieren.");

        // Status ueber WMI
        try
        {
            var products = ThirdPartyAntivirus();
            using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus");
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    bool av = mo["AntivirusEnabled"] as bool? ?? false;
                    bool rtpOn = mo["RealTimeProtectionEnabled"] as bool? ?? false;
                    bool tamper = mo["IsTamperProtected"] as bool? ?? false;
                    int sigAge = Convert.ToInt32(mo["AntivirusSignatureAge"] ?? 0);
                    int scanAge = Convert.ToInt32(mo["FullScanAge"] ?? 0);
                    string? mode = mo["AMRunningMode"]?.ToString();
                    bool passive = mode != null && mode.Contains("Passive", StringComparison.OrdinalIgnoreCase);

                    if ((!av || !rtpOn) && !passive && products.Count == 0)
                        Add(ctx, "Echtzeitschutz ist AUS", 65,
                            "Microsoft Defender Echtzeitschutz ist deaktiviert und kein anderer Virenschutz wurde gefunden.",
                            "Ohne Echtzeitschutz werden Schadprogramme nicht beim Herunterladen oder Starten blockiert.",
                            "Windows-Sicherheit → Viren- & Bedrohungsschutz → Echtzeitschutz einschalten.");
                    else if (products.Count > 0 && (passive || !rtpOn))
                        Add(ctx, "Virenschutz durch Drittanbieter", 0,
                            $"Aktiver Virenschutz: {string.Join(", ", products)}. Defender laeuft im passiven Modus.",
                            "Das ist normal, wenn ein anderes Antivirenprogramm installiert ist.",
                            "Nur ein Virenschutz sollte aktiv sein – mehrere gleichzeitig fuehren zu Konflikten.");

                    if (av && sigAge > 7)
                        Add(ctx, "Virensignaturen veraltet", sigAge > 30 ? 40 : 20,
                            $"Die Defender-Signaturen sind {sigAge} Tage alt.",
                            "Neue Malware wird nur mit aktuellen Signaturen erkannt. Blockierte Updates sind auch ein Malware-Symptom.",
                            "Windows-Sicherheit → Viren- & Bedrohungsschutz → Schutzupdates → Nach Updates suchen.");

                    if (av && !tamper)
                        Add(ctx, "Manipulationsschutz ist aus", 20,
                            "Der Defender-Manipulationsschutz (Tamper Protection) ist deaktiviert.",
                            "Ohne Manipulationsschutz kann Malware Defender-Einstellungen aendern oder Ausnahmen hinzufuegen.",
                            "Windows-Sicherheit → Viren- & Bedrohungsschutz → Einstellungen verwalten → Manipulationsschutz einschalten.");

                    if (av && scanAge > 60 && scanAge < 10000)
                        Add(ctx, "Lange kein vollstaendiger Virenscan", 5,
                            $"Der letzte vollstaendige Defender-Scan liegt {scanAge} Tage zurueck.",
                            "Ein vollstaendiger Scan prueft auch ruhende Dateien.",
                            "Gelegentlich einen vollstaendigen Scan ausfuehren.");
                }
            }
        }
        catch (ManagementException) { ctx.Note("Defender-Status per WMI nicht abrufbar."); }
        catch (UnauthorizedAccessException) { ctx.Note("Defender-Status: Zugriff verweigert."); }
    }

    public static List<string> ThirdPartyAntivirus()
    {
        var list = new List<string>();
        try
        {
            using var s = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct");
            foreach (ManagementObject mo in s.Get())
            {
                using (mo)
                {
                    string name = mo["displayName"]?.ToString() ?? "";
                    uint state = Convert.ToUInt32(mo["productState"] ?? 0);
                    bool enabled = ((state >> 12) & 0xF) == 1;
                    if (enabled && !name.Contains("Defender", StringComparison.OrdinalIgnoreCase)) list.Add(name);
                }
            }
        }
        catch { }
        return list;
    }

    private static readonly string[] BroadExclusions =
    [
        @"c:\", @"c:\users", @"c:\windows", @"c:\programdata", @"%temp%", @"%appdata%", @"%localappdata%", @"\appdata", @"\temp",
        @"c:\users\public", @"\downloads", @"\desktop", "*", @"c:\program files",
    ];

    private void ScanDefenderExclusions(ScanContext ctx)
    {
        const string root = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions";
        var entries = new List<(string Kind, string Value, string Key)>();
        foreach (var (kind, sub) in new[] { ("Pfad", "Paths"), ("Dateiendung", "Extensions"), ("Prozess", "Processes"), ("IP-Adresse", "IpAddresses") })
        {
            foreach (var key in new[] { $@"{root}\{sub}", $@"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\{sub}" })
                foreach (var (name, _) in RegistryUtil.Values(key))
                    if (!string.IsNullOrWhiteSpace(name)) entries.Add((kind, name, key));
        }

        if (entries.Count == 0)
        {
            if (!ctx.IsElevated) ctx.Note("Defender-Ausnahmen sind nur mit Adminrechten lesbar.");
            return;
        }

        foreach (var (kind, value, key) in entries)
        {
            string v = value.ToLowerInvariant().TrimEnd('\\');
            bool broad = kind == "Dateiendung" && v.TrimStart('.', '*') is "exe" or "dll" or "ps1" or "bat" or "vbs" or "js" or "scr"
                         || kind == "Pfad" && BroadExclusions.Any(b => v == b.TrimEnd('\\') || v.EndsWith(b.TrimEnd('\\')) && b.StartsWith('\\'));
            bool userWritable = kind == "Pfad" && Knowledge.LocationClassifier.IsUserWritable(Knowledge.LocationClassifier.Classify(PathUtil.Normalize(value) + "\\x"));
            bool scriptHost = kind == "Prozess" && ExecutableAssessor.LolBins.Contains(Path.GetFileName(v));

            int weight = broad || scriptHost ? 65 : userWritable ? 40 : 15;
            var f = Add(ctx, $"Defender-Ausnahme ({kind}): {value}", weight,
                $"Microsoft Defender prueft {(kind == "Pfad" ? "den Ordner" : kind == "Prozess" ? "den Prozess" : "die " + kind)} \"{value}\" nicht.",
                broad || scriptHost
                    ? "Diese Ausnahme ist so weit gefasst, dass Malware dort ungestoert liegen kann. Angreifer fuegen genau solche Ausnahmen nach einem Einbruch hinzu."
                    : "Ausnahmen sind manchmal fuer Spiele oder Entwicklertools noetig, werden aber auch von Malware gesetzt, um sich zu verstecken.",
                "Pruefen, ob Sie (oder ein bekanntes Programm) die Ausnahme angelegt haben. Falls nicht: entfernen und einen vollstaendigen Scan des Ordners durchfuehren.",
                key);
            f.Actions.Add(new RemediationAction
            {
                Kind = RemediationKind.RemoveDefenderExclusion,
                Label = "Ausnahme entfernen",
                Target = value,
                Argument = kind switch { "Pfad" => "ExclusionPath", "Dateiendung" => "ExclusionExtension", "Prozess" => "ExclusionProcess", _ => "ExclusionIpAddress" },
            });
        }
    }

    // ------------------------------------------------------------------
    // Firewall / UAC / SmartScreen
    // ------------------------------------------------------------------

    private void ScanFirewall(ScanContext ctx)
    {
        const string fw = @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
        const string pol = @"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall";
        foreach (var (profile, label) in new[] { ("DomainProfile", "Domaene"), ("StandardProfile", "Privat"), ("PublicProfile", "Oeffentlich") })
        {
            int? enabled = RegistryUtil.GetInt($@"{pol}\{profile}", "EnableFirewall") ?? RegistryUtil.GetInt($@"{fw}\{profile}", "EnableFirewall");
            if (enabled == 0)
                Add(ctx, $"Firewall aus: Profil '{label}'", profile == "PublicProfile" ? 50 : 35,
                    $"Die Windows-Firewall ist fuer das Netzwerkprofil '{label}' deaktiviert.",
                    "Ohne Firewall sind alle offenen Dienste aus dem Netzwerk erreichbar. Malware schaltet die Firewall gern ab, um Fernzugriff zu ermoeglichen.",
                    "Windows-Sicherheit → Firewall- & Netzwerkschutz → Firewall fuer alle Profile einschalten (sofern keine andere Firewall aktiv ist).", $@"{fw}\{profile}");
        }

        if (RegistryUtil.GetInt(@"HKLM\SYSTEM\CurrentControlSet\Services\mpssvc", "Start") == 4)
            Add(ctx, "Firewall-Dienst deaktiviert", 55, "Der Dienst 'mpssvc' (Windows-Firewall) ist deaktiviert.",
                "Ohne diesen Dienst funktioniert die Firewall nicht.", "Dienst wieder auf 'Automatisch' stellen.");
    }

    private void ScanUac(ScanContext ctx)
    {
        const string sys = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        if (RegistryUtil.GetInt(sys, "EnableLUA") == 0)
            Add(ctx, "Benutzerkontensteuerung (UAC) deaktiviert", 55,
                "Die Benutzerkontensteuerung ist komplett ausgeschaltet.",
                "Jedes Programm laeuft damit sofort mit vollen Adminrechten – Malware kann ungehindert das System veraendern.",
                "Systemsteuerung → Benutzerkonten → Einstellungen der Benutzerkontensteuerung aendern → Standard waehlen, neu starten.", sys)
                .Actions.Add(new RemediationAction { Kind = RemediationKind.RestoreRegistryValue, Label = "UAC einschalten", Target = sys, Argument = "EnableLUA=1" });
        else if (RegistryUtil.GetInt(sys, "ConsentPromptBehaviorAdmin") == 0)
            Add(ctx, "UAC fragt nicht nach", 30,
                "Administratoren werden bei Rechteerhoehung nicht gefragt.",
                "Programme koennen still Adminrechte erhalten.",
                "UAC-Regler mindestens auf die Standardstufe stellen.", sys);

        if (RegistryUtil.GetInt(sys, "LocalAccountTokenFilterPolicy") == 1)
            Add(ctx, "Remote-UAC-Filter deaktiviert", 25,
                "LocalAccountTokenFilterPolicy=1: Lokale Admins erhalten auch ueber das Netzwerk volle Rechte.",
                "Erleichtert Angreifern die Ausbreitung im Netzwerk (Pass-the-Hash).",
                "Wert entfernen, sofern nicht bewusst fuer Fernverwaltung gesetzt.", sys);
    }

    private void ScanSmartScreen(ScanContext ctx)
    {
        if (RegistryUtil.GetInt(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen") == 0
            || string.Equals(RegistryUtil.GetString(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled"), "Off", StringComparison.OrdinalIgnoreCase))
            Add(ctx, "SmartScreen deaktiviert", 30,
                "Windows SmartScreen ist ausgeschaltet.",
                "SmartScreen warnt vor unbekannten heruntergeladenen Programmen und Phishing-Seiten – eine wichtige Schutzschicht gegen Phishing.",
                "Windows-Sicherheit → App- & Browsersteuerung → Zuverlaessigkeitsbasierter Schutz einschalten.");
    }

    // ------------------------------------------------------------------
    // Anmeldeschutz
    // ------------------------------------------------------------------

    private void ScanCredentialProtection(ScanContext ctx)
    {
        const string wdigest = @"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
        if (RegistryUtil.GetInt(wdigest, "UseLogonCredential") == 1)
            Add(ctx, "WDigest speichert Passwoerter im Klartext", 70,
                "UseLogonCredential=1: Windows haelt Anmeldepasswoerter im Klartext im Speicher.",
                "Angreifer setzen diesen Wert, um danach mit Mimikatz Passwoerter im Klartext auszulesen. Seit Windows 8.1 standardmaessig aus.",
                "Wert auf 0 setzen bzw. entfernen, neu anmelden und alle Passwoerter aendern.", wdigest)
                .Actions.Add(new RemediationAction { Kind = RemediationKind.RestoreRegistryValue, Label = "Auf 0 setzen", Target = wdigest, Argument = "UseLogonCredential=0" });

        const string lsa = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
        int? ppl = RegistryUtil.GetInt(lsa, "RunAsPPL");
        if (ppl is null or 0)
            Add(ctx, "LSA-Schutz nicht aktiv", 5,
                "Der Prozess lsass.exe laeuft nicht als geschuetzter Prozess.",
                "Der LSA-Schutz erschwert das Auslesen von Passwoertern aus dem Speicher deutlich.",
                "Windows-Sicherheit → Geraetesicherheit → Kernisolierung → 'Schutz der lokalen Sicherheitsautoritaet' aktivieren.", lsa);

        const string wl = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        if (RegistryUtil.GetString(wl, "AutoAdminLogon") == "1" && !string.IsNullOrEmpty(RegistryUtil.GetString(wl, "DefaultPassword")))
            Add(ctx, "Automatische Anmeldung mit Klartext-Passwort", 45,
                $"Benutzer '{RegistryUtil.GetString(wl, "DefaultUserName")}' meldet sich automatisch an; das Passwort steht im Klartext in der Registry.",
                "Jedes Programm kann das Passwort aus der Registry lesen.",
                "Automatische Anmeldung deaktivieren (netplwiz) und Passwort aendern.", wl);
    }

    private void ScanRemoteAccess(ScanContext ctx)
    {
        const string ts = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";
        if (RegistryUtil.GetInt(ts, "fDenyTSConnections") == 0)
        {
            bool nla = RegistryUtil.GetInt($@"{ts}\WinStations\RDP-Tcp", "UserAuthentication") != 0;
            Add(ctx, nla ? "Remotedesktop ist aktiviert" : "Remotedesktop ohne Netzwerkauthentifizierung", nla ? 15 : 40,
                "Andere koennen sich per Remotedesktop (RDP, Port 3389) an diesem PC anmelden.",
                "RDP ist eines der haeufigsten Einfallstore fuer Ransomware – besonders wenn es aus dem Internet erreichbar ist. " +
                "Telefonbetrueger lassen es sich ausserdem gern aktivieren.",
                "Falls Sie RDP nicht nutzen: Einstellungen → System → Remotedesktop → Aus.", ts);
        }

        const string smb = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
        bool smb1 = RegistryUtil.GetInt(smb, "SMB1") == 1
                    || (RegistryUtil.GetInt(@"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start") is int s && s != 4);
        if (smb1)
            Add(ctx, "Veraltetes SMBv1-Protokoll aktiv", 35,
                "Das unsichere Dateifreigabe-Protokoll SMBv1 ist aktiviert.",
                "Ueber SMBv1 verbreiteten sich WannaCry und NotPetya. Es wird praktisch nie mehr benoetigt.",
                "Windows-Features → 'Unterstuetzung fuer SMB 1.0/CIFS-Dateifreigabe' deaktivieren.");

        if (RegistryUtil.GetInt(@"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp") == 1)
            Add(ctx, "Remoteunterstuetzung erlaubt", 5,
                "Windows-Remoteunterstuetzung ist zugelassen.",
                "Wird bei Support-Betrug missbraucht.",
                "Deaktivieren, falls nicht benoetigt (Systemeigenschaften → Remote).");
    }

    // ------------------------------------------------------------------
    // Updates & Plattform
    // ------------------------------------------------------------------

    private void ScanUpdates(ScanContext ctx)
    {
        if (RegistryUtil.GetInt(@"HKLM\SYSTEM\CurrentControlSet\Services\wuauserv", "Start") == 4)
            Add(ctx, "Windows Update ist deaktiviert", 50,
                "Der Windows-Update-Dienst ist deaktiviert.",
                "Ohne Updates bleiben bekannte Sicherheitsluecken offen. Manche Malware deaktiviert Updates gezielt.",
                "Dienst 'Windows Update' wieder auf 'Manuell' stellen und Updates installieren.");

        if (RegistryUtil.GetInt(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate") == 1)
            Add(ctx, "Automatische Updates per Richtlinie aus", 30,
                "Eine Richtlinie verhindert automatische Updates.",
                "Sicherheitsupdates werden nicht installiert.",
                "Richtlinie entfernen, sofern nicht von Ihrer IT gesetzt.");

        try
        {
            DateTime? newest = null;
            using var s = new ManagementObjectSearcher("SELECT InstalledOn FROM Win32_QuickFixEngineering");
            foreach (ManagementObject mo in s.Get())
                using (mo)
                    if (DateTime.TryParse(mo["InstalledOn"]?.ToString(), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var d)
                        && (newest == null || d > newest))
                        newest = d;
            if (newest is { } last && (DateTime.Now - last).TotalDays > 60)
                Add(ctx, "Lange keine Windows-Updates installiert", (DateTime.Now - last).TotalDays > 120 ? 35 : 20,
                    $"Das letzte Update wurde am {last:d} installiert.",
                    "Monatliche Updates schliessen aktiv ausgenutzte Sicherheitsluecken.",
                    "Einstellungen → Windows Update → Nach Updates suchen.");
        }
        catch { }
    }

    private void ScanPlatform(ScanContext ctx)
    {
        int build = SystemEnv.BuildNumber;
        if (build < 22000 && DateTime.Now > new DateTime(2025, 10, 14))
            Add(ctx, "Windows 10 erhaelt keine regulaeren Sicherheitsupdates mehr", 30,
                "Der Support fuer Windows 10 endete am 14.10.2025.",
                "Neue Sicherheitsluecken werden ohne ESU-Programm nicht mehr geschlossen.",
                "Auf Windows 11 aktualisieren (sofern die Hardware es unterstuetzt) oder am ESU-Programm teilnehmen.");

        if (RegistryUtil.GetInt(@"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled") == 0)
            Add(ctx, "Secure Boot ist deaktiviert", 15,
                "Der sichere Start (Secure Boot) ist im UEFI ausgeschaltet.",
                "Secure Boot verhindert, dass Bootkits/Rootkits vor Windows geladen werden.",
                "Im UEFI/BIOS Secure Boot aktivieren (Achtung bei Dual-Boot-Systemen).");

        string? policy = RegistryUtil.GetString(@"HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy");
        if (policy is "Unrestricted" or "Bypass")
            Add(ctx, $"PowerShell-Ausfuehrungsrichtlinie: {policy}", 10,
                "PowerShell fuehrt Skripte ohne jede Pruefung aus.",
                "Die Richtlinie ist keine echte Sicherheitsgrenze, 'Bypass' systemweit ist aber ungewoehnlich.",
                "Auf 'RemoteSigned' setzen: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine");
    }
}
