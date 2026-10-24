using System.Text;

namespace ScanMe.Core.Knowledge;

/// <summary>
/// Leichtgewichtige Inhaltssignaturen ("YARA light"): Zeichenketten, die in bekannten
/// Malware-Familien und Hacktools vorkommen. Eine Signatur schlaegt erst an, wenn
/// <see cref="Signature.MinHits"/> ihrer Muster in derselben Datei gefunden werden.
/// Bewusst nur spezifische Marker – generische API-Namen erzeugen zu viele Fehlalarme.
/// </summary>
public static class ContentSignatures
{
    [Flags]
    public enum Target { Pe = 1, Script = 2, Any = Pe | Script }

    public sealed record Signature(string Name, string Family, int Weight, int MinHits, Target AppliesTo, string[] Patterns, string Explanation);

    public static readonly IReadOnlyList<Signature> All =
    [
        new("Mimikatz", "Credential Dumper", 80, 2, Target.Any, ["sekurlsa::", "mimikatz", "kerberos::golden", "lsadump::", "gentilkiwi", "mimilib", "privilege::debug"],
            "Werkzeug zum Auslesen von Passwörtern und Kerberos-Tickets aus dem Speicher."),
        new("Cobalt Strike / Meterpreter", "Post-Exploitation", 75, 2, Target.Any, ["ReflectiveLoader", "beacon.dll", "beacon.x64.dll", "meterpreter", "metsrv.dll", "stdapi_sys_", "%s as %s\\%s: %d"],
            "Fernsteuerungs-Implantat, wie es von Angreifergruppen und Ransomware-Banden eingesetzt wird."),
        new("Browser-Passwortdieb (Infostealer)", "Infostealer", 70, 5, Target.Any,
            ["\\Login Data", "\\Local State", "\\Network\\Cookies", "\\Web Data", "wallet.dat", "\\Exodus\\", "\\Electrum\\", "encrypted_key", "\\Telegram Desktop\\tdata", "\\discord\\Local Storage\\leveldb", "\\Mozilla\\Firefox\\Profiles", "logins.json", "key4.db", "\\Atomic\\Local Storage", "nkbihfbeogaeaoehlefnkodbefgpgknn"],
            "Liest gespeicherte Browser-Passwörter, Cookies, Krypto-Wallets und Messenger-Sitzungen aus. Typisch für RedLine, Vidar, Lumma, Raccoon & Co. – oft per Phishing verteilt."),
        new("Discord-Token-Grabber", "Infostealer", 65, 2, Target.Any, ["discord.com/api/webhooks/", "discordapp.com/api/webhooks/", "\\discord\\Local Storage\\leveldb", "dQw4w9WgXcQ:", "tokenprotector"],
            "Stiehlt Discord-Anmeldetoken und sendet sie an einen Webhook."),
        new("Telegram-Exfiltration", "Infostealer", 45, 2, Target.Any, ["api.telegram.org/bot", "/sendDocument", "sendMessage?chat_id="],
            "Schickt Daten an einen Telegram-Bot – häufiger Ausleitungskanal von Stealern."),
        new("Remote Access Trojaner", "RAT", 70, 2, Target.Pe,
            ["AsyncRAT", "AsyncClient", "QuasarRAT", "Quasar.Client", "njRAT", "Remcos_Mutex", "Remcos v", "DCRat", "DarkComet", "NanoCore Client", "XWorm", "VenomRAT", "AveMaria", "WARZONE", "NetWire", "Pastebin", "|Hwid|", "\\Remcos\\"],
            "Fernsteuerungs-Trojaner: Angreifer können Bildschirm, Tastatur, Kamera und Dateien kontrollieren."),
        new("Keylogger", "Spyware", 50, 3, Target.Any, ["[ENTER]", "[BACKSPACE]", "[CAPSLOCK]", "[TAB]", "[ESC]", "[DEL]", "keylog.txt", "[CTRL]"],
            "Zeichnet Tastatureingaben (Passwörter!) auf."),
        new("Krypto-Miner", "Miner", 55, 1, Target.Any, ["stratum+tcp://", "stratum+ssl://", "--donate-level", "pool.minexmr", "moneroocean.stream", "xmrig.com", "pool.supportxmr"],
            "Schürft heimlich Kryptowährung auf Ihre Kosten (Strom, Hardware-Verschleiss)."),
        new("Ransomware-Merkmale", "Ransomware", 75, 3, Target.Any, ["vssadmin delete shadows", "vssadmin.exe delete shadows", "wbadmin delete catalog", "recoveryenabled no", "Your files have been encrypted", "All your files are encrypted", ".onion", "decryptor", "ransom"],
            "Enthält typische Bausteine von Erpressungstrojanern (Schattenkopien löschen, Lösegeldforderung)."),
        new("AMSI-/ETW-Umgehung", "Evasion", 55, 1, Target.Script, ["AmsiScanBuffer", "amsiInitFailed", "AmsiUtils", "EtwEventWrite"],
            "Versucht, die Malware-Erkennung von Windows auszuschalten."),
        new("Tor-Kommunikation", "C2", 40, 1, Target.Pe, ["DotNetTor", "Tor.Proxy", "TorSharp", "\\Tor\\tor.exe", "Knapcode.TorSharp", "obfs4proxy", "TorControlPort", "HiddenServiceDir"],
            "Bringt einen eigenen Tor-Client mit, um anonym mit einem Steuerserver zu kommunizieren – für normale Programme sehr ungewöhnlich."),
        new("IP-Fingerprinting", "Recon", 25, 2, Target.Any, ["api.ipify.org", "ipinfo.io", "api.seeip.org", "ip-api.com", "checkip.amazonaws.com", "icanhazip.com", "wtfismyip.com", "ifconfig.me", "myexternalip.com", "geoplugin.net"],
            "Fragt mehrere Dienste nach der öffentlichen IP-Adresse ab – typisch für Stealer/RATs, die das Opfer beim Angreifer registrieren."),
        new("Obfuskiertes PowerShell", "Loader", 35, 3, Target.Script, ["FromBase64String", "-bxor", "[char[]]", "Invoke-Expression", "IEX(", "IEX (", "[System.Convert]::", "-join", "[Reflection.Assembly]::Load", "GzipStream", "-split", "[array]::Reverse"],
            "Stark verschleierter Skriptcode – legitime Skripte sind selten so aufgebaut."),
    ];

    /// <summary>Durchsucht Dateiinhalt (ASCII + UTF-16) nach Signaturen.</summary>
    public static List<(Signature Sig, List<string> Hits)> Scan(byte[] data, Target target)
    {
        string ascii = Encoding.Latin1.GetString(data);
        string utf16 = target == Target.Pe && data.Length > 1 ? Encoding.Unicode.GetString(data) : "";
        var result = new List<(Signature, List<string>)>();
        foreach (var sig in All.Concat(Updates.RuleStore.ContentSignatures))
        {
            if ((sig.AppliesTo & target) == 0) continue;
            var hits = sig.Patterns
                .Where(p => ascii.Contains(p, StringComparison.OrdinalIgnoreCase) || (utf16.Length > 0 && utf16.Contains(p, StringComparison.OrdinalIgnoreCase)))
                .ToList();
            if (hits.Count >= sig.MinHits) result.Add((sig, hits));
        }
        return result;
    }

    /// <summary>Bekannte Packer/Protector-Sektionsnamen.</summary>
    public static readonly Dictionary<string, string> PackerSections = new(StringComparer.Ordinal)
    {
        ["UPX0"] = "UPX", ["UPX1"] = "UPX", [".MPRESS1"] = "MPRESS", [".MPRESS2"] = "MPRESS", [".aspack"] = "ASPack",
        [".adata"] = "ASProtect", [".themida"] = "Themida", [".winlice"] = "WinLicense", [".vmp0"] = "VMProtect", [".vmp1"] = "VMProtect",
        [".enigma1"] = "Enigma", [".petite"] = "Petite", [".nsp0"] = "NsPack", [".packed"] = "Packer", ["pebundle"] = "PEBundle",
    };
}
