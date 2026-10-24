using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography.X509Certificates;
using ScanMe.Core.Engine;
using ScanMe.Core.Inventory;
using ScanMe.Core.Models;
using ScanMe.Core.Trust;
using ScanMe.Core.Util;

namespace ScanMe.Core.Scanners;

/// <summary>
/// Netzwerkverbindungen pro Prozess, offene Ports, Hosts-Datei, Proxy/PAC, DNS und Root-Zertifikate.
/// </summary>
public sealed class NetworkScanner : IScanner
{
    public string Id => "network";
    public string Name => "Netzwerk";
    public string Description => "Verbindungen ins Internet, offene Ports, Hosts-Datei, Proxy, DNS und manipulierte Zertifikate.";
    public bool InQuickScan => true;

    /// <summary>Ports, die typischerweise von Hacking-Tools, RATs oder Tor genutzt werden.</summary>
    private static readonly Dictionary<int, string> SuspiciousPorts = new()
    {
        [4444] = "Metasploit-Standardport",
        [4445] = "Metasploit",
        [1337] = "'Leet'-Port (Hacker-Tools)",
        [31337] = "Back Orifice / Hacker-Tools",
        [5555] = "Android-Debug / RATs",
        [6666] = "IRC (Botnetze)",
        [6667] = "IRC (Botnetze)",
        [6697] = "IRC (Botnetze)",
        [9001] = "Tor",
        [9030] = "Tor",
        [9050] = "Tor-Proxy",
        [9150] = "Tor-Browser-Proxy",
        [1604] = "DarkComet-RAT",
        [5552] = "njRAT",
        [7707] = "RATs",
        [8808] = "RATs",
        [3333] = "Mining-Pool (Stratum)",
        [14444] = "Monero-Mining-Pool",
        [45700] = "Monero-Mining-Pool",
    };

    public Task ScanAsync(ScanContext ctx)
    {
        ctx.Status("Lese Verbindungstabellen …");
        var connections = ConnectionTable.Capture();
        var snap = ProcessScanner.GetSnapshot(ctx);

        AnalyzeConnections(ctx, connections, snap);
        ctx.ThrowIfCancelled();
        ctx.Status("Hosts-Datei …");
        ScanHostsFile(ctx);
        ctx.Status("Proxy & DNS …");
        ScanProxy(ctx);
        ScanDns(ctx);
        ctx.Status("Root-Zertifikate …");
        ScanRootCertificates(ctx);
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------

    private void AnalyzeConnections(ScanContext ctx, List<Connection> connections, ProcessSnapshot snap)
    {
        foreach (var group in connections.Where(c => c.Pid > 4).GroupBy(c => c.Pid))
        {
            ctx.ThrowIfCancelled();
            var proc = snap.Get(group.Key);
            string name = proc?.Name ?? $"PID {group.Key}";
            if (SelfIdentity.IsOwnProcess(group.Key, proc?.ImagePath)) continue;
            string? path = proc?.ImagePath ?? ProcessSnapshot.QueryImagePath(group.Key);

            var external = group.Where(c => c.IsEstablished && c.IsExternal).ToList();
            var listeners = group.Where(c => c.Protocol == Protocol.Tcp && c.State == "LISTEN"
                                             && (c.LocalAddress.Equals(IPAddress.Any) || c.LocalAddress.Equals(IPAddress.IPv6Any))).ToList();
            if (external.Count == 0 && listeners.Count == 0) continue;

            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Network,
                Title = $"Netzwerkaktivität: {name}",
                ProcessId = group.Key,
            };

            FileTrustInfo? info = path != null ? ExecutableAssessor.Assess(f, path, ctx.Trust) : null;
            bool lolbin = info?.IsWindowsComponent == true && ExecutableAssessor.LolBins.Contains(name);

            if (external.Count > 0)
            {
                if (info != null && info.Signature != SignatureState.Valid && !ExecutableAssessor.IsGameLibrary(info.Path))
                    f.AddIndicator("NET_UNSIGNED_EXT", $"Unsigniertes Programm mit {external.Count} Verbindung(en) ins Internet", 15);
                if (lolbin)
                    f.AddIndicator("NET_LOLBIN", $"{name} hat eine aktive Internetverbindung – typisch für Downloader/Reverse Shells", 40);
            }

            foreach (var c in external)
                if (SuspiciousPorts.TryGetValue(c.RemotePort, out var why))
                    f.AddIndicator($"NET_PORT_{c.RemotePort}", $"Verbindung zu {c.RemoteAddress}:{c.RemotePort} ({why})", 35);

            if (listeners.Count > 0 && info is { IsMicrosoftSigned: false })
            {
                f.AddIndicator("NET_LISTEN", $"Lauscht auf {listeners.Count} Port(s) für Verbindungen aus dem Netzwerk", info.Signature == SignatureState.Valid ? 5 : 20);
                foreach (var l in listeners)
                    if (SuspiciousPorts.TryGetValue(l.LocalPort, out var why))
                        f.AddIndicator($"NET_LPORT_{l.LocalPort}", $"Lauscht auf Port {l.LocalPort} ({why})", info.Signature == SignatureState.Valid ? 10 : 40);
            }

            int score = f.Indicators.Sum(i => i.Weight);
            if (score < 15) continue;

            var remotes = external.Select(c => $"{c.RemoteAddress}:{c.RemotePort}").Distinct().Take(25).ToList();
            f.Detail("Verbindungen ins Internet", remotes.Count > 0 ? string.Join(", ", remotes) : "keine")
             .Detail("Offene Ports", listeners.Count > 0 ? string.Join(", ", listeners.Select(l => l.LocalPort).Distinct().Order()) : "keine")
             .Detail("Kommandozeile", proc?.CommandLine);

            f.Description = $"{name} (PID {group.Key}) hat {external.Count} aktive Internetverbindung(en)" +
                            (listeners.Count > 0 ? $" und wartet auf {listeners.Count} Port(s) auf eingehende Verbindungen." : ".");
            f.Explanation = "Malware muss mit ihrem Betreiber kommunizieren (Command & Control) oder gestohlene Daten senden. " +
                            "Unbekannte, unsignierte Programme mit Internetverbindung verdienen deshalb einen genauen Blick.";
            f.Recommendation = score >= 50
                ? "Prozess beenden, Programmdatei in Quarantäne verschieben und die Ziel-IP-Adressen (z. B. auf abuseipdb.com) prüfen."
                : "Prüfen, ob Sie das Programm kennen und ob es ins Internet darf. Ziel-IPs ggf. auf abuseipdb.com nachschlagen.";
            if (!f.IsProtected)
                f.Actions.Insert(0, new RemediationAction { Kind = RemediationKind.KillProcess, Label = "Prozess beenden", Target = group.Key.ToString() });
            ctx.Add(f);
        }
    }

    // ------------------------------------------------------------------
    // Hosts-Datei
    // ------------------------------------------------------------------

    /// <summary>Domains, deren Umleitung auf Phishing oder Sabotage der Sicherheitssoftware hindeutet.</summary>
    private static readonly string[] SensitiveDomains =
    [
        "microsoft.com", "windowsupdate.com", "windows.com", "live.com", "office.com", "office365.com", "outlook.com", "msftncsi.com",
        "google.com", "gmail.com", "apple.com", "icloud.com", "facebook.com", "instagram.com", "paypal.com", "amazon.", "ebay.",
        "sparkasse", "volksbank", "commerzbank", "deutsche-bank", "db.com", "postbank", "ing.de", "dkb.de", "comdirect", "n26",
        "consorsbank", "targobank", "hypovereinsbank", "santander", "bank", "steam", "discord", "binance", "coinbase", "kraken",
        "virustotal", "malwarebytes", "kaspersky", "avast", "avg.com", "eset", "bitdefender", "norton", "symantec", "mcafee",
        "sophos", "trendmicro", "f-secure", "gdata", "avira", "defender", "wdcp.microsoft", "smartscreen",
    ];

    private void ScanHostsFile(ScanContext ctx)
    {
        string hosts = Path.Combine(PathUtil.System32, @"drivers\etc\hosts");
        string[] lines;
        try { lines = File.ReadAllLines(hosts); }
        catch { ctx.Note("Hosts-Datei nicht lesbar."); return; }

        var entries = new List<(string Ip, string Host)>();
        foreach (var raw in lines)
        {
            string line = raw.Split('#')[0].Trim();
            if (line.Length == 0) continue;
            var parts = line.Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            foreach (var h in parts.Skip(1)) entries.Add((parts[0], h.ToLowerInvariant()));
        }
        if (entries.Count == 0) return;

        var sensitive = entries.Where(e => SensitiveDomains.Any(d => e.Host.Contains(d))).ToList();
        var ordinary = entries.Except(sensitive)
            .Where(e => !(e.Host is "localhost" or "localhost.localdomain" or "kubernetes.docker.internal" or "host.docker.internal" or "gateway.docker.internal"))
            .ToList();

        if (sensitive.Count > 0)
        {
            bool blocksSecurity = sensitive.Any(e => e.Ip is "0.0.0.0" or "127.0.0.1" or "::1");
            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Network,
                Title = "Hosts-Datei leitet wichtige Domains um",
                FilePath = hosts,
                Description = "Die Hosts-Datei enthält Einträge für: " + string.Join(", ", sensitive.Select(e => $"{e.Host} → {e.Ip}").Take(15)),
                Explanation = blocksSecurity
                    ? "Malware blockiert über die Hosts-Datei häufig Windows Update und Antivirus-Hersteller, damit sie nicht entdeckt wird."
                    : "Werden Bank-, Mail- oder Login-Domains auf fremde IP-Adressen umgeleitet, landen Sie trotz korrekter Adresse auf einer Phishing-Seite.",
                Recommendation = "Prüfen Sie, ob Sie diese Einträge selbst gesetzt haben (z. B. Werbeblocker). Falls nicht: Hosts-Datei auf Standard zurücksetzen und Passwörter der betroffenen Dienste ändern.",
            };
            f.AddIndicator("HOSTS_SENSITIVE", $"{sensitive.Count} sicherheitsrelevante Domain(s) umgeleitet", blocksSecurity ? 55 : 65);
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.RestoreHostsFile, Label = "Hosts-Datei zurücksetzen (mit Sicherung)", Target = hosts });
            f.Actions.Add(new RemediationAction { Kind = RemediationKind.OpenLocation, Label = "Speicherort öffnen", Target = hosts, RequiresConfirmation = false });
            ctx.Add(f);
        }

        if (ordinary.Count > 0)
        {
            bool adblock = ordinary.Count > 50 && ordinary.All(e => e.Ip is "0.0.0.0" or "127.0.0.1");
            var f = new Finding
            {
                ScannerId = Id,
                Category = FindingCategory.Network,
                Title = "Benutzerdefinierte Einträge in der Hosts-Datei",
                FilePath = hosts,
                Description = $"{ordinary.Count} Eintrag/Einträge, z. B.: " + string.Join(", ", ordinary.Take(8).Select(e => $"{e.Host} → {e.Ip}")),
                Explanation = adblock ? "Sieht nach einer Werbe-/Tracking-Sperrliste aus." : "Die Hosts-Datei überschreibt DNS für einzelne Domains.",
                Recommendation = "Nur relevant, wenn Sie die Einträge nicht selbst vorgenommen haben.",
            };
            f.AddIndicator("HOSTS_CUSTOM", "Benutzerdefinierte Hosts-Einträge", adblock ? 0 : 10);
            ctx.Add(f);
        }
    }

    // ------------------------------------------------------------------
    // Proxy / PAC
    // ------------------------------------------------------------------

    private void ScanProxy(ScanContext ctx)
    {
        foreach (var hive in RegistryUtil.LoadedUserHives())
        {
            string key = $@"{hive}\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
            bool enabled = RegistryUtil.GetInt(key, "ProxyEnable") == 1;
            string? server = RegistryUtil.GetString(key, "ProxyServer");
            string? pac = RegistryUtil.GetString(key, "AutoConfigURL");
            string user = RegistryUtil.SidToUser(hive[4..]);

            if (!string.IsNullOrWhiteSpace(pac))
            {
                bool remotePac = pac.StartsWith("http", StringComparison.OrdinalIgnoreCase) && !pac.Contains("wpad", StringComparison.OrdinalIgnoreCase);
                var f = new Finding
                {
                    ScannerId = Id,
                    Category = FindingCategory.Network,
                    Title = $"Proxy-Autokonfiguration (PAC) aktiv – {user}",
                    Location = key,
                    Description = $"Der Webverkehr wird über das Skript {pac} gesteuert.",
                    Explanation = "Banking-Trojaner setzen PAC-Skripte, um nur Bank-Webseiten über einen Angreifer-Server umzuleiten. " +
                                  "In Firmennetzen ist ein PAC-Skript dagegen normal.",
                    Recommendation = "Wenn dies kein Firmen-PC ist: In Einstellungen → Netzwerk und Internet → Proxy das Setup-Skript deaktivieren und Passwörter ändern.",
                };
                f.AddIndicator("PAC", "Proxy-Autokonfiguration gesetzt", remotePac ? 45 : 25);
                f.Detail("PAC-URL", pac);
                f.Actions.Add(new RemediationAction { Kind = RemediationKind.DeleteRegistryValue, Label = "PAC-Eintrag entfernen (mit Sicherung)", Target = key, Argument = "AutoConfigURL" });
                ctx.Add(f);
            }

            if (enabled && !string.IsNullOrWhiteSpace(server))
            {
                bool local = server.Contains("127.0.0.1") || server.Contains("localhost");
                var f = new Finding
                {
                    ScannerId = Id,
                    Category = FindingCategory.Network,
                    Title = $"Manueller Proxy aktiv – {user}",
                    Location = key,
                    Description = $"Webverkehr läuft über den Proxy {server}.",
                    Explanation = local
                        ? "Ein lokaler Proxy kann von Entwickler-Tools (Fiddler, Burp) stammen – oder von Adware, die Webseiten manipuliert."
                        : "Ein Proxy sieht (und kann verändern), was Sie im Web tun. Malware setzt Proxys, um Datenverkehr mitzulesen.",
                    Recommendation = "Prüfen, ob Sie den Proxy kennen (Firma, VPN, Entwickler-Tool). Falls nicht: deaktivieren.",
                };
                f.AddIndicator("PROXY", "Systemweiter Proxy gesetzt", local ? 20 : 35);
                f.Detail("Proxy", server).Detail("Ausnahmen", RegistryUtil.GetString(key, "ProxyOverride"));
                f.Actions.Add(new RemediationAction { Kind = RemediationKind.RestoreRegistryValue, Label = "Proxy deaktivieren", Target = key, Argument = "ProxyEnable=0" });
                ctx.Add(f);
            }
        }
    }

    // ------------------------------------------------------------------
    // DNS
    // ------------------------------------------------------------------

    private static readonly HashSet<string> KnownResolvers =
    [
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
        "94.140.14.14", "94.140.15.15", "76.76.2.0", "76.76.10.0", "185.228.168.9", "185.228.169.9", "45.90.28.0", "45.90.30.0",
        "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9",
    ];

    private void ScanDns(ScanContext ctx)
    {
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var unknown = nic.GetIPProperties().DnsAddresses
                    .Where(ip => NetUtil.IsPublic(ip) && !KnownResolvers.Contains(ip.ToString()))
                    .ToList();
                if (unknown.Count == 0) continue;

                var f = new Finding
                {
                    ScannerId = Id,
                    Category = FindingCategory.Network,
                    Title = $"Unbekannter DNS-Server: {nic.Name}",
                    Description = $"Der Netzwerkadapter \"{nic.Name}\" nutzt den/die DNS-Server {string.Join(", ", unknown)}.",
                    Explanation = "DNS übersetzt Webadressen in IP-Adressen. 'DNS-Changer'-Malware trägt eigene Server ein, um Sie auf gefälschte Seiten zu leiten. " +
                                  "Viele Internetanbieter nutzen jedoch eigene, öffentliche DNS-Server – dann ist alles in Ordnung.",
                    Recommendation = "Prüfen, ob die IP zu Ihrem Internetanbieter, VPN oder Ihrer Firma gehört (z. B. per Whois). Im Zweifel DNS auf 'Automatisch' stellen.",
                };
                f.AddIndicator("DNS_UNKNOWN", "Nicht-standardmäßiger öffentlicher DNS-Server", 15);
                ctx.Add(f);
            }
        }
        catch { }
    }

    // ------------------------------------------------------------------
    // Root-Zertifikate
    // ------------------------------------------------------------------

    private static readonly string[] BadRootNames =
    [
        "superfish", "edellroot", "dsdtestprovider", "komodia", "privdog", "do_not_trust", "fiddler", "mitmproxy",
        "portswigger", "burp", "charles proxy", "sendori", "wajam", "lenovo visual discovery", "adguard personal", "zscaler",
    ];

    private void ScanRootCertificates(ScanContext ctx)
    {
        foreach (var location in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
        {
            try
            {
                using var store = new X509Store(StoreName.Root, location);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                foreach (var cert in store.Certificates)
                {
                    string subject = cert.Subject;
                    string? bad = BadRootNames.FirstOrDefault(b => subject.Contains(b, StringComparison.OrdinalIgnoreCase));
                    bool recentSelfSigned = cert.Subject == cert.Issuer && (DateTime.Now - cert.NotBefore).TotalDays < 180;
                    if (bad == null && !recentSelfSigned) continue;

                    bool devTool = bad is "fiddler" or "mitmproxy" or "portswigger" or "burp" or "charles proxy" or "zscaler" or "adguard personal";
                    var f = new Finding
                    {
                        ScannerId = Id,
                        Category = FindingCategory.Network,
                        Title = $"Verdächtiges Stammzertifikat: {cert.GetNameInfo(X509NameType.SimpleName, false)}",
                        Location = $"Zertifikatspeicher {location}\\Root",
                        Description = $"Im Speicher vertrauenswürdiger Stammzertifizierungsstellen liegt \"{subject}\" (gültig ab {cert.NotBefore:d}).",
                        Explanation = "Wer ein eigenes Stammzertifikat installiert, kann verschlüsselte HTTPS-Verbindungen unbemerkt mitlesen und verändern " +
                                      "(Man-in-the-Middle). Adware wie 'Superfish' nutzte genau das." +
                                      (devTool ? " Hier handelt es sich vermutlich um ein Entwickler-/Firmenwerkzeug." : ""),
                        Recommendation = devTool
                            ? "Wenn Sie das Tool nicht (mehr) nutzen, Zertifikat über certmgr.msc entfernen."
                            : "Zertifikat über certmgr.msc (Benutzer) bzw. certlm.msc (Computer) entfernen, sofern Sie es nicht bewusst installiert haben.",
                    };
                    f.AddIndicator(bad != null ? "ROOT_KNOWN_BAD" : "ROOT_RECENT", bad != null ? $"Bekanntes Abfang-Zertifikat ({bad})" : "Kürzlich hinzugefügtes selbstsigniertes Stammzertifikat",
                        bad != null ? (devTool ? 20 : 70) : 20);
                    f.Detail("Fingerabdruck", cert.Thumbprint).Detail("Aussteller", cert.Issuer).Detail("Gültig bis", cert.NotAfter.ToString("d"));
                    ctx.Add(f);
                }
            }
            catch { }
        }
    }
}
