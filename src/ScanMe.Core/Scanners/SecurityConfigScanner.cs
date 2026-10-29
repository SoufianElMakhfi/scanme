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
                "Malware setzt diese Richtlinie häufig, um den Virenschutz auszuschalten. Ohne anderen Virenschutz ist der PC ungeschützt.",
                "Wenn kein anderer Virenschutz installiert ist: Wert 'DisableAntiSpyware' entfernen und neu starten.", policy)
                .Actions.Add(new RemediationAction { Kind = RemediationKind.DeleteRegistryValue, Label = "Richtlinie entfernen (mit Sicherung)", Target = policy, Argument = "DisableAntiSpyware" });

        const string rtp = policy + @"\Real-Time Protection";
        if (RegistryUtil.GetInt(rtp, "DisableRealtimeMonitoring") == 1 || RegistryUtil.GetInt(rtp, "DisableBehaviorMonitoring") == 1)
            Add(ctx, "Defender-Echtzeitschutz per Richtlinie deaktiviert", 60,
                "Eine Richtlinie schaltet den Echtzeit- bzw. Verhaltensschutz ab.",
                "Ohne Echtzeitschutz werden Schadprogramme beim Start nicht blockiert. Typische Maßnahme von Angreifern.",
                "Richtlinie entfernen, sofern sie nicht von Ihrer IT gesetzt wurde.", rtp);

        if (RegistryUtil.GetInt(@"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend", "Start") == 4)
            Add(ctx, "Defender-Dienst deaktiviert", 50,
                "Der Dienst 'WinDefend' ist deaktiviert.",
                "Das ist nur normal, wenn ein anderes Antivirenprogramm aktiv ist.",
                "Prüfen, ob ein anderer Virenschutz läuft. Falls nicht: Defender reaktivieren.");

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
                    long sigAge = Convert.ToInt64(mo["AntivirusSignatureAge"] ?? 0);
                    // UInt32 im WMI-Schema; 4294967295 heisst "noch nie" – passt nicht in int
                    long scanAge = Convert.ToInt64(mo["FullScanAge"] ?? 0);
                    string? mode = mo["AMRunningMode"]?.ToString();
                    bool passive = mode != null && mode.Contains("Passive", StringComparison.OrdinalIgnoreCase);

                    if ((!av || !rtpOn) && !passive && products.Count == 0)
                        Add(ctx, "Echtzeitschutz ist AUS", 65,
                            "Microsoft Defender Echtzeitschutz ist deaktiviert und kein anderer Virenschutz wurde gefunden.",
                            "Ohne Echtzeitschutz werden Schadprogramme nicht beim Herunterladen oder Starten blockiert.",
                            "Windows-Sicherheit → Viren- & Bedrohungsschutz → Echtzeitschutz einschalten.");
                    else if (products.Count > 0 && (passive || !rtpOn))
                        Add(ctx, "Virenschutz durch Drittanbieter", 0,
                            $"Aktiver Virenschutz: {string.Join(", ", products)}. Defender läuft im passiven Modus.",
                            "Das ist normal, wenn ein anderes Antivirenprogramm installiert ist.",
                            "Nur ein Virenschutz sollte aktiv sein – mehrere gleichzeitig führen zu Konflikten.");

                    if (av && sigAge > 7)
                        Add(ctx, "Virensignaturen veraltet", sigAge > 30 ? 40 : 20,
                            $"Die Defender-Signaturen sind {sigAge} Tage alt.",
                            "Neue Malware wird nur mit aktuellen Signaturen erkannt. Blockierte Updates sind auch ein Malware-Symptom.",
                            "Windows-Sicherheit → Viren- & Bedrohungsschutz → Schutzupdates → Nach Updates suchen.");

                    if (av && !tamper)
                        Add(ctx, "Manipulationsschutz ist aus", 20,
                            "Der Defender-Manipulationsschutz (Tamper Protection) ist deaktiviert.",
                            "Ohne Manipulationsschutz kann Malware Defender-Einstellungen ändern oder Ausnahmen hinzufügen.",
                            "Windows-Sicherheit → Viren- & Bedrohungsschutz → Einstellungen verwalten → Manipulationsschutz einschalten.");

                    if (av && scanAge > 60 && scanAge < 10000)
                        Add(ctx, "Lange kein vollständiger Virenscan", 5,
                            $"Der letzte vollständige Defender-Scan liegt {scanAge} Tage zurück.",
                            "Ein vollständiger Scan prüft auch ruhende Dateien.",
                            "Gelegentlich einen vollständigen Scan ausführen.");
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

        // Originalpfade der Quarantaene: Ausnahmen, die darauf zeigen, hat sehr wahrscheinlich die Malware selbst angelegt.
        var quarantined = Actions.Quarantine.List().Select(q => q.OriginalPath).ToList();

        foreach (var (kind, value, key) in entries)
        {
            var indicators = Knowledge.ExclusionRisk.Assess(kind, value, quarantined);
            bool malware = indicators.Any(i => i.Code is "EXCL_QUARANTINED" or "EXCL_MASQUERADE");
            bool cheat = indicators.Any(i => i.Code == "EXCL_CHEAT");
            bool orphaned = indicators.Any(i => i.Code == "EXCL_ORPHANED");

            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.SecurityConfig,
                Title = $"Defender-Ausnahme ({kind}): {value}",
                Location = key,
                Description = $"Microsoft Defender prüft {(kind == "Pfad" ? "den Pfad" : kind == "Prozess" ? "den Prozess" : "die " + kind)} \"{value}\" nicht.",
                Explanation = malware
                    ? "Diese Ausnahme gehört sehr wahrscheinlich zu Schadsoftware: Malware trägt sich selbst als Ausnahme ein, damit Defender sie nie prüft. " +
                      "Bleibt die Ausnahme bestehen, wird die Malware bei einer erneuten Infektion wieder ignoriert."
                    : cheat
                        ? "Cheat-, Crack- und Loader-Programme verlangen oft eine Ausnahme, weil Virenscanner sie erkennen. Genau so gelangen Krypto-Miner und Passwortdiebe auf PCs."
                        : "Ausnahmen sind manchmal für Spiele oder Entwicklertools nötig, werden aber auch von Malware gesetzt, um sich zu verstecken.",
                Recommendation = malware || orphaned
                    ? "Ausnahme entfernen – sie wird nicht mehr gebraucht und schützt nur noch Schadsoftware. Unbedenklich ist sie nur, wenn Sie den Pfad selbst eingetragen haben und das Programm kennen."
                    : cheat
                        ? "Ausnahme entfernen und das Programm im Ordner mit Defender scannen. Behalten nur, wenn Sie der Quelle vertrauen – bei Cheats/Cracks ist das praktisch nie der Fall."
                        : "Prüfen: Windows-Sicherheit → Viren- & Bedrohungsschutz → Einstellungen verwalten → Ausschlüsse. Unbedenklich, wenn Sie bzw. ein bekanntes Programm (z. B. Entwicklungsumgebung) die Ausnahme angelegt haben; sonst entfernen.",
            };
            f.Indicators.AddRange(indicators);
            ctx.Add(f);
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
        foreach (var (profile, label) in new[] { ("DomainProfile", "Domäne"), ("StandardProfile", "Privat"), ("PublicProfile", "Öffentlich") })
        {
            int? enabled = RegistryUtil.GetInt($@"{pol}\{profile}", "EnableFirewall") ?? RegistryUtil.GetInt($@"{fw}\{profile}", "EnableFirewall");
            if (enabled == 0)
                Add(ctx, $"Firewall aus: Profil '{label}'", profile == "PublicProfile" ? 50 : 35,
                    $"Die Windows-Firewall ist für das Netzwerkprofil '{label}' deaktiviert.",
                    "Ohne Firewall sind alle offenen Dienste aus dem Netzwerk erreichbar. Malware schaltet die Firewall gern ab, um Fernzugriff zu ermöglichen.",
                    "Windows-Sicherheit → Firewall- & Netzwerkschutz → Firewall für alle Profile einschalten (sofern keine andere Firewall aktiv ist).", $@"{fw}\{profile}");
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
                "Jedes Programm läuft damit sofort mit vollen Adminrechten – Malware kann ungehindert das System verändern.",
                "Systemsteuerung → Benutzerkonten → Einstellungen der Benutzerkontensteuerung ändern → Standard wählen, neu starten.", sys)
                .Actions.Add(new RemediationAction { Kind = RemediationKind.RestoreRegistryValue, Label = "UAC einschalten", Target = sys, Argument = "EnableLUA=1" });
        else if (RegistryUtil.GetInt(sys, "ConsentPromptBehaviorAdmin") == 0)
            Add(ctx, "UAC fragt nicht nach", 30,
                "Administratoren werden bei Rechteerhöhung nicht gefragt.",
                "Programme können still Adminrechte erhalten.",
                "UAC-Regler mindestens auf die Standardstufe stellen.", sys);

        if (RegistryUtil.GetInt(sys, "LocalAccountTokenFilterPolicy") == 1)
            Add(ctx, "Remote-UAC-Filter deaktiviert", 25,
                "LocalAccountTokenFilterPolicy=1: Lokale Admins erhalten auch über das Netzwerk volle Rechte.",
                "Erleichtert Angreifern die Ausbreitung im Netzwerk (Pass-the-Hash).",
                "Wert entfernen, sofern nicht bewusst für Fernverwaltung gesetzt.", sys);
    }

    private void ScanSmartScreen(ScanContext ctx)
    {
        if (RegistryUtil.GetInt(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen") == 0
            || string.Equals(RegistryUtil.GetString(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled"), "Off", StringComparison.OrdinalIgnoreCase))
            Add(ctx, "SmartScreen deaktiviert", 30,
                "Windows SmartScreen ist ausgeschaltet.",
                "SmartScreen warnt vor unbekannten heruntergeladenen Programmen und Phishing-Seiten – eine wichtige Schutzschicht gegen Phishing.",
                "Windows-Sicherheit → App- & Browsersteuerung → Zuverlässigkeitsbasierter Schutz einschalten.");
    }

    // ------------------------------------------------------------------
    // Anmeldeschutz
    // ------------------------------------------------------------------

    private void ScanCredentialProtection(ScanContext ctx)
    {
        const string wdigest = @"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
        if (RegistryUtil.GetInt(wdigest, "UseLogonCredential") == 1)
            Add(ctx, "WDigest speichert Passwörter im Klartext", 70,
                "UseLogonCredential=1: Windows hält Anmeldepasswörter im Klartext im Speicher.",
                "Angreifer setzen diesen Wert, um danach mit Mimikatz Passwörter im Klartext auszulesen. Seit Windows 8.1 standardmäßig aus.",
                "Wert auf 0 setzen bzw. entfernen, neu anmelden und alle Passwörter ändern.", wdigest)
                .Actions.Add(new RemediationAction { Kind = RemediationKind.RestoreRegistryValue, Label = "Auf 0 setzen", Target = wdigest, Argument = "UseLogonCredential=0" });

        const string lsa = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
        int? ppl = RegistryUtil.GetInt(lsa, "RunAsPPL");
        if (ppl is null or 0)
            Add(ctx, "LSA-Schutz nicht aktiv", 5,
                "Der Prozess lsass.exe läuft nicht als geschützter Prozess.",
                "Der LSA-Schutz erschwert das Auslesen von Passwörtern aus dem Speicher deutlich.",
                "Windows-Sicherheit → Gerätesicherheit → Kernisolierung → 'Schutz der lokalen Sicherheitsautorität' aktivieren.", lsa);

        const string wl = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        if (RegistryUtil.GetString(wl, "AutoAdminLogon") == "1" && !string.IsNullOrEmpty(RegistryUtil.GetString(wl, "DefaultPassword")))
            Add(ctx, "Automatische Anmeldung mit Klartext-Passwort", 45,
                $"Benutzer '{RegistryUtil.GetString(wl, "DefaultUserName")}' meldet sich automatisch an; das Passwort steht im Klartext in der Registry.",
                "Jedes Programm kann das Passwort aus der Registry lesen.",
                "Automatische Anmeldung deaktivieren (netplwiz) und Passwort ändern.", wl);
    }

    private void ScanRemoteAccess(ScanContext ctx)
    {
        const string ts = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";
        if (RegistryUtil.GetInt(ts, "fDenyTSConnections") == 0)
        {
            bool nla = RegistryUtil.GetInt($@"{ts}\WinStations\RDP-Tcp", "UserAuthentication") != 0;
            Add(ctx, nla ? "Remotedesktop ist aktiviert" : "Remotedesktop ohne Netzwerkauthentifizierung", nla ? 15 : 40,
                "Andere können sich per Remotedesktop (RDP, Port 3389) an diesem PC anmelden.",
                "RDP ist eines der häufigsten Einfallstore für Ransomware – besonders wenn es aus dem Internet erreichbar ist. " +
                "Telefonbetrüger lassen es sich ausserdem gern aktivieren.",
                "Falls Sie RDP nicht nutzen: Einstellungen → System → Remotedesktop → Aus.", ts);
        }

        const string smb = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
        bool smb1 = RegistryUtil.GetInt(smb, "SMB1") == 1
                    || (RegistryUtil.GetInt(@"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start") is int s && s != 4);
        if (smb1)
            Add(ctx, "Veraltetes SMBv1-Protokoll aktiv", 35,
                "Das unsichere Dateifreigabe-Protokoll SMBv1 ist aktiviert.",
                "Über SMBv1 verbreiteten sich WannaCry und NotPetya. Es wird praktisch nie mehr benötigt.",
                "Windows-Features → 'Unterstützung für SMB 1.0/CIFS-Dateifreigabe' deaktivieren.");

        if (RegistryUtil.GetInt(@"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp") == 1)
            Add(ctx, "Remoteunterstützung erlaubt", 5,
                "Windows-Remoteunterstützung ist zugelassen.",
                "Wird bei Support-Betrug missbraucht.",
                "Deaktivieren, falls nicht benötigt (Systemeigenschaften → Remote).");
    }

    // ------------------------------------------------------------------
    // Updates & Plattform
    // ------------------------------------------------------------------

    private void ScanUpdates(ScanContext ctx)
    {
        if (RegistryUtil.GetInt(@"HKLM\SYSTEM\CurrentControlSet\Services\wuauserv", "Start") == 4)
            Add(ctx, "Windows Update ist deaktiviert", 50,
                "Der Windows-Update-Dienst ist deaktiviert.",
                "Ohne Updates bleiben bekannte Sicherheitslücken offen. Manche Malware deaktiviert Updates gezielt.",
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
                    "Monatliche Updates schließen aktiv ausgenutzte Sicherheitslücken.",
                    "Einstellungen → Windows Update → Nach Updates suchen.");
        }
        catch { }
    }

    private void ScanPlatform(ScanContext ctx)
    {
        int build = SystemEnv.BuildNumber;
        if (build < 22000 && DateTime.Now > new DateTime(2025, 10, 14))
            Add(ctx, "Windows 10 erhält keine regulären Sicherheitsupdates mehr", 30,
                "Der Support für Windows 10 endete am 14.10.2025.",
                "Neue Sicherheitslücken werden ohne ESU-Programm nicht mehr geschlossen.",
                "Auf Windows 11 aktualisieren (sofern die Hardware es unterstützt) oder am ESU-Programm teilnehmen.");

        if (RegistryUtil.GetInt(@"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled") == 0)
            Add(ctx, "Secure Boot ist deaktiviert", 15,
                "Der sichere Start (Secure Boot) ist im UEFI ausgeschaltet.",
                "Secure Boot verhindert, dass Bootkits/Rootkits vor Windows geladen werden.",
                "Im UEFI/BIOS Secure Boot aktivieren (Achtung bei Dual-Boot-Systemen).");

        string? policy = RegistryUtil.GetString(@"HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy");
        if (policy is "Unrestricted" or "Bypass")
            Add(ctx, $"PowerShell-Ausführungsrichtlinie: {policy}", 10,
                "PowerShell führt Skripte ohne jede Prüfung aus.",
                "Die Richtlinie ist keine echte Sicherheitsgrenze, 'Bypass' systemweit ist aber ungewöhnlich.",
                "Auf 'RemoteSigned' setzen: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine");
    }
}
