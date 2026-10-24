using ScanMe.Core.Models;

namespace ScanMe.Core.Engine;

/// <summary>
/// Uebersetzt einen technischen Fund in eine Entscheidungshilfe fuer Laien:
/// Ampel (Verdict), ein Satz ohne Fachbegriffe, Ja/Nein-Fragen und ein konkreter Schritt fuer "kenne ich nicht".
///
/// Grundidee: Nicht jeder Hinweis ist ein Beweis. Fehlende Signatur, ungewoehnlicher Ort oder fehlende
/// Herstellerangaben treffen auf viele normale Programme zu (Spiele, kleine Tools, Open Source, eigene Skripte).
/// Erst "harte" Indikatoren – Tarnung, Malware-Code, Defender-Treffer – rechtfertigen ein klares "Handeln".
/// </summary>
public static class PlainLanguage
{
    /// <summary>Kontext-Hinweise: allein kein Beleg fuer Schadsoftware.</summary>
    private static readonly HashSet<string> WeakCodes = new(StringComparer.Ordinal)
    {
        "SIG_NONE", "SIG_NONE_SCRIPT", "NO_METADATA", "RECENT", "MOTW", "NET_UNSIGNED_EXT", "NET_LISTEN", "HIDDEN_BACKGROUND",
        "SCRIPT_LOCATION", "PS_FLAGGED", "BLOAT", "RESOURCE", "WEAK_ONLY", "NO_PATH", "FILE_MISSING", "TASK_SYSTEM", "VIA_HOST",
        "UNRESOLVED", "SVC_UNQUOTED", "EXCL_USERPATH", "EXCL_ORPHANED", "EXCL_OTHER", "RUNMRU", "PS_PROFILE", "GAME_LIBRARY",
        "RDP_LOCAL", "HOSTS_CUSTOM", "DIR_HIDDEN", "APPDATA_ROOT", "RANDOM_DIR", "PACKER", "HIGH_ENTROPY", "RWX_SECTION",
        "TASK_HIDDEN_FLAG", "ADS", "CONFIG", "COMPAT", "MANY_ADMINS", "RECENT_INSTALLS", "NEW_AUTOSTART", "BASE",
    };

    /// <summary>Starke Belege – fuehren unabhaengig vom Score zu "Handeln".</summary>
    private static readonly HashSet<string> HardCodes = new(StringComparer.Ordinal)
    {
        "HIDDEN_PROCESS", "MASQUERADE", "LOOKALIKE", "FAKE_MICROSOFT", "DEFENDER_DETECTED", "DEF_ACTIVE", "IMAGE_DELETED",
        "ACCESSIBILITY_REPLACED", "TASK_NO_SD", "DRV_MINER", "EXCL_QUARANTINED", "EXCL_COVERS_MALWARE", "EXCL_MASQUERADE",
        "RANSOM_NOTE", "RANSOM_EXT", "ADS_PE", "RTLO", "DOUBLE_EXT", "DOC_SPAWN", "MULTI_INSTANCE", "BAD_PARENT",
        "IN_TASKS_DIR", "SIG_INVALID", "DRV_UNSIGNED", "DRV_BAD_SIG",
    };

    public static void Apply(Finding f)
    {
        f.Questions.Clear();
        var positives = f.Indicators.Where(i => i.Weight > 0).ToList();
        var evidence = positives.Where(i => !WeakCodes.Contains(i.Code) && !i.Code.StartsWith("LOC_", StringComparison.Ordinal)).ToList();
        int evidenceScore = evidence.Sum(i => i.Weight);
        bool hard = evidence.Any(i => HardCodes.Contains(i.Code) || i.Code.StartsWith("CONTENT_", StringComparison.Ordinal));
        // Vergangene PowerShell-Ereignisse: Ob es gewollt war, weiss nur der Nutzer (Skripte, KI-Tools, Automatisierung).
        bool userIntentDecides = f.ScannerId == "eventlog" && f.Title.StartsWith("PowerShell-Skript", StringComparison.Ordinal);

        f.Verdict =
            positives.Count == 0 || (f.Severity == Severity.Info && evidenceScore == 0) ? Verdict.Info
            : hard && !userIntentDecides ? Verdict.Act
            : evidenceScore >= 60 && !userIntentDecides && f.Severity >= Severity.High ? Verdict.Act
            : evidenceScore >= 15 ? Verdict.Check
            : Verdict.LikelyHarmless;

        if (f.IsProtected && f.Verdict == Verdict.LikelyHarmless) f.Verdict = Verdict.Info;

        AddQuestions(f);
        f.PlainSummary = Summary(f, evidence, positives);
        f.IfUnknown = IfUnknown(f);
    }

    private static string Name(Finding f) =>
        f.FilePath != null ? Path.GetFileName(f.FilePath) : f.Title.Contains(':') ? f.Title[(f.Title.IndexOf(':') + 1)..].Trim() : f.Title;

    private static bool Has(Finding f, string codePrefix) => f.Indicators.Any(i => i.Weight > 0 && i.Code.StartsWith(codePrefix, StringComparison.Ordinal));

    private static void AddQuestions(Finding f)
    {
        if (f.Verdict == Verdict.Info) return;
        string name = Name(f);

        if (f.ScannerId == "eventlog" && f.Title.StartsWith("PowerShell-Skript", StringComparison.Ordinal))
        {
            string when = f.Details.GetValueOrDefault("Zeitpunkt") ?? "diesem Zeitpunkt";
            f.Questions.Add($"Haben Sie am {when} selbst Befehle in PowerShell eingegeben, ein Skript gestartet oder mit einem KI-Assistenten bzw. einem Automatisierungs-Tool gearbeitet?");
            f.Questions.Add("Wurden Sie kurz davor auf einer Webseite aufgefordert, Tasten wie Win+R und Strg+V zu drücken („Ich bin kein Roboter“)? Dann war es ein Angriff.");
            return;
        }
        if (f.ScannerId == "baseline" && Has(f, "NEW_SINCE_BASELINE"))
        {
            string since = f.Details.GetValueOrDefault("Seit") ?? "dem sauberen Zustand";
            f.Questions.Add($"Haben Sie seit {since} selbst etwas installiert, eingerichtet oder aktualisiert, zu dem „{Name(f)}“ gehören könnte?");
            return;
        }
        if (Has(f, "REMOTE_TOOL") || Has(f, "TOOL_REMOTEACCESS"))
        {
            f.Questions.Add($"Haben Sie {name} selbst installiert, weil Sie es nutzen – oder hat Sie jemand am Telefon, per Nachricht oder über eine Webseite dazu aufgefordert?");
            return;
        }
        if (f.Title.StartsWith("Defender-Ausnahme", StringComparison.Ordinal))
        {
            f.Questions.Add("Haben Sie diese Ausnahme selbst eingetragen – zum Beispiel, weil ein Spiel, Mod oder Tool sonst nicht startete?");
            if (Has(f, "EXCL_CHEAT")) f.Questions.Add("Vertrauen Sie der Quelle dieses Programms wirklich? Cheats und Cracks sind der häufigste Weg, auf dem Passwortdiebe auf PCs kommen.");
            return;
        }
        switch (f.Category)
        {
            case FindingCategory.Driver when Has(f, "DRV_VULNERABLE"):
                f.Questions.Add("Nutzen Sie das zugehörige Hersteller-Programm (z. B. MSI Center, AMD Ryzen Master, RGB- oder Lüftersteuerung)?");
                break;
            case FindingCategory.Browser:
                f.Questions.Add($"Haben Sie „{name}“ selbst im Browser installiert und nutzen es noch?");
                break;
            case FindingCategory.Account:
                f.Questions.Add("Kennen Sie dieses Benutzerkonto, und wurde es von Ihnen oder Ihrer Familie/Firma angelegt?");
                break;
            case FindingCategory.Persistence:
                f.Questions.Add($"Haben Sie „{name}“ selbst installiert, und soll es automatisch mit Windows starten?");
                break;
            case FindingCategory.SecurityConfig when Has(f, "VULN"):
                break; // keine Frage – einfach aktualisieren
            case FindingCategory.SecurityConfig:
                f.Questions.Add("Haben Sie diese Einstellung bewusst so gesetzt (oder Ihre Firma/IT)?");
                break;
            default:
                if (f.FilePath != null)
                    f.Questions.Add($"Kennen Sie „{name}“ – haben Sie das Programm bzw. die Datei selbst installiert oder heruntergeladen (z. B. Spiel, Tool, eigenes Skript)?");
                break;
        }
    }

    private static string Summary(Finding f, List<Indicator> evidence, List<Indicator> positives)
    {
        string top = evidence.OrderByDescending(i => i.Weight).Select(i => i.Text).FirstOrDefault()
                     ?? positives.OrderByDescending(i => i.Weight).Select(i => i.Text).FirstOrDefault() ?? "";
        switch (f.Verdict)
        {
            case Verdict.Info:
                return "Nur zur Information – hier besteht keine Gefahr und Sie müssen nichts tun.";
            case Verdict.Act:
                return $"Hier gibt es deutliche Hinweise auf Schadsoftware oder einen Angriff: {top}. Bitte handeln Sie – auch wenn Ihnen der Name bekannt vorkommt, denn Malware tarnt sich gezielt.";
            case Verdict.Check:
                return f.Questions.Count > 0
                    ? $"Das kann harmlos oder gefährlich sein – entscheidend ist, ob Sie es selbst veranlasst haben. Auffällig ist: {top}."
                    : Has(f, "VULN")
                        ? $"Keine Schadsoftware, aber eine Sicherheitslücke: {top} Bitte aktualisieren."
                        : $"Bitte kurz ansehen: {top}.";
            default:
                bool onlyUnsigned = positives.All(i => i.Code is "SIG_NONE" or "NO_METADATA" or "RECENT" or "NET_UNSIGNED_EXT" or "HIDDEN_BACKGROUND" or "GAME_LIBRARY" || i.Code.StartsWith("LOC_", StringComparison.Ordinal));
                return onlyUnsigned
                    ? "Wahrscheinlich harmlos. Das Programm hat keine digitale Unterschrift (Signatur). Das ist bei Spielen, kleinen Tools, Open-Source-Programmen und eigenen Skripten normal – eine Signatur kostet Geld. Allein ist das kein Hinweis auf Schadsoftware."
                    : $"Wahrscheinlich harmlos. Auffällig ist nur: {string.Join("; ", positives.OrderByDescending(i => i.Weight).Take(2).Select(i => i.Text))}. Das trifft auch auf viele normale Programme zu.";
        }
    }

    private static string IfUnknown(Finding f)
    {
        if (f.Verdict == Verdict.Info) return "";
        if (f.ScannerId == "eventlog" && f.Title.StartsWith("PowerShell-Skript", StringComparison.Ordinal))
            return "Dann hat jemand oder etwas anderes PowerShell benutzt. Starten Sie einen vollständigen Scan, ändern Sie wichtige Passwörter von einem anderen Gerät aus und melden Sie sich überall ab („Von allen Geräten abmelden“).";
        if (Has(f, "REMOTE_TOOL") || Has(f, "TOOL_REMOTEACCESS"))
            return "Programm sofort deinstallieren, Internet kurz trennen, bei Ihrer Bank anrufen und Passwörter von einem anderen Gerät aus ändern. Seriöse Firmen rufen nie unaufgefordert an, um Fernwartung einzurichten.";
        if (f.Title.StartsWith("Defender-Ausnahme", StringComparison.Ordinal))
            return "Klicken Sie auf „Ausnahme entfernen“. Das lässt sich jederzeit rückgängig machen.";
        var primary = f.Actions.FirstOrDefault(a => a.Kind is RemediationKind.KillProcess or RemediationKind.QuarantineFile or RemediationKind.DisableAutostart
            or RemediationKind.DisableScheduledTask or RemediationKind.DisableService or RemediationKind.DeleteRegistryValue or RemediationKind.RemoveWmiSubscription);
        return primary != null
            ? $"Klicken Sie auf „{primary.Label}“ – ScanMe sichert vorher alles, Sie können es unter „Quarantäne & Verlauf“ jederzeit rückgängig machen. Danach einen vollständigen Scan starten."
            : f.Recommendation;
    }
}
