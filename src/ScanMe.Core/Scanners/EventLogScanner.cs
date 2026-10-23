using System.Diagnostics.Eventing.Reader;
using System.Net;
using ScanMe.Core.Engine;
using ScanMe.Core.Inventory;
using ScanMe.Core.Knowledge;
using ScanMe.Core.Models;
using ScanMe.Core.Util;

namespace ScanMe.Core.Scanners;

/// <summary>
/// Forensische Auswertung der Windows-Ereignisprotokolle: Spuren eines (frueheren) Angriffs.
/// </summary>
public sealed class EventLogScanner : IScanner
{
    public string Id => "eventlog";
    public string Name => "Ereignisprotokolle (Forensik)";
    public string Description => "Gelöschte Protokolle, neue Dienste/Konten, Brute-Force, RDP-Anmeldungen, Defender-Änderungen, verdächtige PowerShell.";
    public bool InQuickScan => false;

    private const int MaxEvents = 2000;

    public Task ScanAsync(ScanContext ctx)
    {
        int days = ctx.Options.EventLogDays;
        long ms = days * 24L * 3600 * 1000;
        if (!ctx.IsElevated) ctx.Note("Das Sicherheitsprotokoll ist nur mit Adminrechten lesbar – Anmelde- und Kontoereignisse fehlen.");

        ctx.Status("Gelöschte Protokolle …");
        LogCleared(ctx, ms, days);
        ctx.ThrowIfCancelled();
        ctx.Status("Neu installierte Dienste …");
        NewServices(ctx, ms);
        ctx.ThrowIfCancelled();
        ctx.Status("Konten und Gruppen …");
        AccountChanges(ctx, ms);
        ctx.ThrowIfCancelled();
        ctx.Status("Anmeldeversuche …");
        Logons(ctx, ms, days);
        ctx.ThrowIfCancelled();
        ctx.Status("Defender-Ereignisse …");
        DefenderEvents(ctx, ms);
        ctx.ThrowIfCancelled();
        ctx.Status("PowerShell-Protokoll …");
        PowerShellEvents(ctx, ms);
        return Task.CompletedTask;
    }

    private static IEnumerable<EventRecord> Query(ScanContext ctx, string log, string xpath)
    {
        EventLogReader reader;
        try
        {
            reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = true });
        }
        catch (EventLogNotFoundException) { yield break; }
        catch (UnauthorizedAccessException) { yield break; }
        catch (EventLogException) { yield break; }

        using (reader)
        {
            int n = 0;
            while (n++ < MaxEvents)
            {
                EventRecord? rec;
                try { rec = reader.ReadEvent(); }
                catch { yield break; }
                if (rec == null) yield break;
                using (rec) yield return rec;
            }
        }
    }

    private static string Time(long ms) => $"TimeCreated[timediff(@SystemTime) <= {ms}]";

    private static string? Prop(EventRecord r, int i)
    {
        try { return r.Properties.Count > i ? r.Properties[i].Value?.ToString() : null; }
        catch { return null; }
    }

    private Finding NewFinding(string title, FindingCategory cat = FindingCategory.EventLog) =>
        new() { ScannerId = Id, Category = cat, Title = title };

    // ------------------------------------------------------------------

    private void LogCleared(ScanContext ctx, long ms, int days)
    {
        var events = new List<(DateTime When, string Log, string? User)>();
        foreach (var r in Query(ctx, "Security", $"*[System[(EventID=1102) and {Time(ms)}]]"))
            events.Add((r.TimeCreated ?? DateTime.MinValue, "Sicherheit", Prop(r, 1)));
        foreach (var r in Query(ctx, "System", $"*[System[(EventID=104) and {Time(ms)}]]"))
            events.Add((r.TimeCreated ?? DateTime.MinValue, Prop(r, 2) ?? "System", Prop(r, 0)));
        if (events.Count == 0) return;

        var f = NewFinding("Ereignisprotokolle wurden gelöscht");
        f.Description = string.Join("; ", events.Take(10).Select(e => $"{e.When:g}: '{e.Log}' durch {e.User ?? "?"}"));
        f.Explanation = "Angreifer löschen Protokolle, um ihre Spuren zu verwischen. Manche Tuning-/Cleaner-Programme tun das ebenfalls.";
        f.Recommendation = "Haben Sie (oder ein Cleaner wie CCleaner) die Protokolle gelöscht? Falls nicht, ist das ein starkes Indiz für einen Einbruch.";
        f.AddIndicator("LOG_CLEARED", $"{events.Count}x Protokoll in den letzten {days} Tagen gelöscht", events.Any(e => e.Log == "Sicherheit") ? 55 : 35);
        ctx.Add(f);
    }

    private void NewServices(ScanContext ctx, long ms)
    {
        foreach (var r in Query(ctx, "System", $"*[System[Provider[@Name='Service Control Manager'] and (EventID=7045) and {Time(ms)}]]"))
        {
            string name = Prop(r, 0) ?? "?";
            string? image = Prop(r, 1);
            var f = NewFinding($"Neuer Dienst installiert: {name}", FindingCategory.Persistence);
            f.Detail("Installiert am", r.TimeCreated?.ToString("g")).Detail("ImagePath", image).Detail("Starttyp", Prop(r, 3)).Detail("Konto", Prop(r, 4));

            var (exe, payload) = PathUtil.ResolveCommandLine(image);
            if ((payload ?? exe) is { } target) ExecutableAssessor.Assess(f, target, ctx.Trust);
            foreach (var rule in CommandLineRules.Match(image))
                f.AddIndicator("CMD_" + rule.Id, rule.Text, rule.Weight);
            if (image != null && (image.Contains("cmd", StringComparison.OrdinalIgnoreCase) && image.Contains("/c", StringComparison.OrdinalIgnoreCase)
                                  || image.Contains("powershell", StringComparison.OrdinalIgnoreCase)))
                f.AddIndicator("SVC_SHELL", "Dienst führt direkt einen Shell-Befehl aus (typisch für PsExec/Angreifer)", 50);
            if (name.Equals("PSEXESVC", StringComparison.OrdinalIgnoreCase))
                f.AddIndicator("PSEXEC", "PsExec wurde auf diesem PC ausgeführt (Fernsteuerung)", 40);

            if (f.Indicators.Sum(i => i.Weight) < 15) continue;
            f.Description = $"Am {r.TimeCreated:g} wurde der Dienst \"{name}\" installiert: {image}";
            f.Explanation = "Angreifer installieren Dienste, um mit Systemrechten dauerhaft aktiv zu bleiben (MITRE T1543.003).";
            f.Recommendation = "Prüfen, ob dieser Dienst zu einem Programm gehört, das Sie installiert haben.";
            ctx.Add(f);
        }
    }

    private void AccountChanges(ScanContext ctx, long ms)
    {
        foreach (var r in Query(ctx, "Security", $"*[System[(EventID=4720) and {Time(ms)}]]"))
        {
            var f = NewFinding($"Benutzerkonto angelegt: {Prop(r, 0)}", FindingCategory.Account);
            f.Description = $"Am {r.TimeCreated:g} wurde das Konto '{Prop(r, 0)}' von '{Prop(r, 4)}' erstellt.";
            f.Explanation = "Nach einem Einbruch legen Angreifer häufig eigene Konten an.";
            f.Recommendation = "Prüfen, ob Sie dieses Konto angelegt haben.";
            f.AddIndicator("ACCOUNT_CREATED", "Neues lokales Konto", 25);
            ctx.Add(f);
        }

        foreach (var r in Query(ctx, "Security", $"*[System[(EventID=4732) and {Time(ms)}]]"))
        {
            if (Prop(r, 4) != "S-1-5-32-544") continue; // nur Administratoren
            string member = Prop(r, 0) is { Length: > 1 } m && m != "-" ? m : RegistryUtil.SidToUser(Prop(r, 1) ?? "");
            var f = NewFinding($"Zur Administratorgruppe hinzugefügt: {member}", FindingCategory.Account);
            f.Description = $"Am {r.TimeCreated:g} wurde '{member}' von '{Prop(r, 6)}' zu den Administratoren hinzugefügt.";
            f.Explanation = "Angreifer verschaffen sich so dauerhafte Adminrechte (MITRE T1098).";
            f.Recommendation = "Prüfen, ob diese Änderung gewollt war.";
            f.AddIndicator("ADMIN_ADDED", "Benutzer zur Administratorgruppe hinzugefügt", 40);
            ctx.Add(f);
        }
    }

    private void Logons(ScanContext ctx, long ms, int days)
    {
        // Fehlgeschlagene Anmeldungen (Brute-Force / Passwort-Spraying)
        var failed = new List<(string Ip, string User, string Type)>();
        foreach (var r in Query(ctx, "Security", $"*[System[(EventID=4625) and {Time(ms)}]]"))
            failed.Add((Prop(r, 19) ?? "-", Prop(r, 5) ?? "?", Prop(r, 10) ?? "?"));
        if (failed.Count >= 20)
        {
            var bySource = failed.GroupBy(x => x.Ip).OrderByDescending(g => g.Count()).Take(10).ToList();
            bool external = bySource.Any(g => IPAddress.TryParse(g.Key, out var ip) && NetUtil.IsPublic(ip));
            var f = NewFinding($"{failed.Count} fehlgeschlagene Anmeldeversuche");
            f.Description = "Quellen: " + string.Join(", ", bySource.Select(g => $"{g.Key} ({g.Count()}x)")) +
                            ". Benutzernamen: " + string.Join(", ", failed.Select(x => x.User).Distinct().Take(10));
            f.Explanation = external
                ? "Viele Fehlversuche aus dem Internet deuten auf automatisiertes Passwortraten hin – meist über offenes RDP oder SMB."
                : "Viele Fehlversuche können auf Passwortraten im lokalen Netz oder auf ein falsch gespeichertes Passwort hindeuten.";
            f.Recommendation = external
                ? "RDP/SMB nicht direkt ins Internet freigeben (Router-Portweiterleitungen prüfen), starke Passwörter und Kontosperre nutzen."
                : "Prüfen, ob ein Dienst oder Laufwerk mit altem Passwort verbunden ist.";
            f.AddIndicator("BRUTE_FORCE", $"{failed.Count} Fehlversuche in {days} Tagen", external ? 55 : failed.Count > 200 ? 35 : 20);
            ctx.Add(f);
        }

        // Erfolgreiche RDP-Anmeldungen von oeffentlichen IPs
        var rdp = new List<(DateTime When, string User, string Ip)>();
        foreach (var r in Query(ctx, "Security", $"*[System[(EventID=4624) and {Time(ms)}] and EventData[Data[@Name='LogonType']='10']]"))
            rdp.Add((r.TimeCreated ?? DateTime.MinValue, Prop(r, 5) ?? "?", Prop(r, 18) ?? "-"));
        foreach (var r in Query(ctx, "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", $"*[System[(EventID=1149) and {Time(ms)}]]"))
            rdp.Add((r.TimeCreated ?? DateTime.MinValue, Prop(r, 0) ?? "?", Prop(r, 2) ?? "-"));

        var publicRdp = rdp.Where(x => IPAddress.TryParse(x.Ip, out var ip) && NetUtil.IsPublic(ip)).ToList();
        if (publicRdp.Count > 0)
        {
            var f = NewFinding("Remotedesktop-Anmeldungen aus dem Internet");
            f.Description = string.Join("; ", publicRdp.Take(15).Select(x => $"{x.When:g} {x.User} von {x.Ip}"));
            f.Explanation = "Jemand hat sich per Remotedesktop von einer öffentlichen IP-Adresse angemeldet. Wenn Sie das nicht selbst waren, " +
                            "hatte ein Fremder vollen Zugriff auf den PC.";
            f.Recommendation = "Waren Sie das (z. B. von unterwegs)? Falls nicht: PC vom Netz trennen, Passwörter ändern, RDP deaktivieren und Fachleute hinzuziehen.";
            f.AddIndicator("RDP_PUBLIC", $"{publicRdp.Count} RDP-Anmeldung(en) von öffentlichen IPs", 70);
            ctx.Add(f);
        }
        else if (rdp.Count > 0)
        {
            var f = NewFinding("Remotedesktop-Anmeldungen im lokalen Netz");
            f.Description = string.Join("; ", rdp.Take(10).Select(x => $"{x.When:g} {x.User} von {x.Ip}"));
            f.Explanation = "Anmeldungen per Remotedesktop aus dem lokalen Netzwerk.";
            f.Recommendation = "Prüfen, ob diese Anmeldungen bekannt sind.";
            f.AddIndicator("RDP_LOCAL", "RDP-Anmeldungen", 10);
            ctx.Add(f);
        }
    }

    private void DefenderEvents(ScanContext ctx, long ms)
    {
        const string log = "Microsoft-Windows-Windows Defender/Operational";
        var exclusions = new List<string>();
        int rtpOff = 0;
        foreach (var r in Query(ctx, log, $"*[System[(EventID=5007 or EventID=5001) and {Time(ms)}]]"))
        {
            if (r.Id == 5001) { rtpOff++; continue; }
            string? newValue = Prop(r, 3) ?? Prop(r, 2);
            if (newValue != null && newValue.Contains("Exclusions", StringComparison.OrdinalIgnoreCase))
                exclusions.Add($"{r.TimeCreated:g}: {newValue}");
        }

        if (exclusions.Count > 0)
        {
            var f = NewFinding($"Defender-Ausnahmen wurden hinzugefügt ({exclusions.Count})", FindingCategory.SecurityConfig);
            f.Description = string.Join(" | ", exclusions.Take(10).Select(e => TextUtil.Truncate(e, 220)));
            f.Explanation = "Malware fügt nach der Infektion gern Defender-Ausnahmen für ihre eigenen Ordner hinzu.";
            f.Recommendation = "Prüfen, ob Sie diese Ausnahmen selbst angelegt haben (Windows-Sicherheit → Ausschlüsse).";
            f.AddIndicator("DEF_EXCL_ADDED", "Ausnahmen in Defender-Konfiguration hinzugefügt", 30);
            ctx.Add(f);
        }
        if (rtpOff > 0)
        {
            var f = NewFinding($"Defender-Echtzeitschutz wurde {rtpOff}x deaktiviert", FindingCategory.SecurityConfig);
            f.Description = $"Im Zeitraum wurde der Echtzeitschutz {rtpOff}-mal ausgeschaltet.";
            f.Explanation = "Kurzzeitiges Deaktivieren ist manchmal für Installationen nötig – Malware tut es aber ebenfalls.";
            f.Recommendation = "Prüfen, ob Sie den Schutz bewusst deaktiviert haben.";
            f.AddIndicator("DEF_RTP_OFF", "Echtzeitschutz zeitweise deaktiviert", rtpOff > 3 ? 25 : 10);
            ctx.Add(f);
        }
    }

    private void PowerShellEvents(ScanContext ctx, long ms)
    {
        // Level 3 (Warnung) bei 4104: PowerShell selbst hat den Skriptblock als verdaechtig eingestuft.
        var seen = new HashSet<string>();
        foreach (var r in Query(ctx, "Microsoft-Windows-PowerShell/Operational", $"*[System[(EventID=4104) and (Level=3) and {Time(ms)}]]"))
        {
            string script = Prop(r, 2) ?? "";
            string key = script.Length > 200 ? script[..200] : script;
            if (!seen.Add(key) || seen.Count > 15) continue;

            var f = NewFinding($"Verdächtiges PowerShell-Skript ausgeführt ({r.TimeCreated:g})", FindingCategory.Malware);
            f.Description = TextUtil.Truncate(script.Replace("\r", "").Replace("\n", " ⏎ "), 500);
            f.Explanation = "PowerShell protokolliert Skripte, die verdächtige Befehle enthalten, automatisch als Warnung. Das hilft, dateilose Angriffe nachzuvollziehen.";
            f.Recommendation = "Inhalt prüfen. Unbekannte Skripte mit Download-, Verschleierungs- oder Speicherbefehlen deuten auf einen Angriff hin.";
            f.AddIndicator("PS_SUSPICIOUS", "Von PowerShell als verdächtig markierter Skriptblock", 20);
            foreach (var rule in CommandLineRules.Match(script))
                f.AddIndicator("PS_" + rule.Id, rule.Text, Math.Min(rule.Weight, 40));
            f.Detail("Skriptpfad", Prop(r, 4));
            ctx.Add(f);
        }
    }
}
