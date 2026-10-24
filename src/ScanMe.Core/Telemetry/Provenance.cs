using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Xml.Linq;
using ScanMe.Core.Models;
using ScanMe.Core.Trust;
using ScanMe.Core.Util;

namespace ScanMe.Core.Telemetry;

/// <summary>Ein Glied der Startkette: welches Programm, mit welchem Befehl.</summary>
public sealed record ProcessNode(string Image, string? CommandLine, int ProcessId, DateTime? Started)
{
    public string Name => Path.GetFileName(Image);
}

public enum OriginKind { Unknown, Trusted, RunDialog, Suspicious }

public sealed record ProcessChain(IReadOnlyList<ProcessNode> Nodes, string Source)
{
    /// <summary>Kette lesbar: "Code.exe → pwsh.exe → powershell.exe" (aelteste zuerst).</summary>
    public string Describe() => string.Join(" → ", Nodes.Reverse().Select(n => n.Name));
}

public sealed record OriginVerdict(OriginKind Kind, string Reason, ProcessNode? Decisive);

/// <summary>
/// Beantwortet "Wer hat das gestartet?" aus Sysmon (Ereignis 1) oder dem Sicherheitsprotokoll (4688).
/// So laesst sich ein Befehl aus Ihrem eigenen Terminal oder KI-Tool von einem Befehl unterscheiden,
/// den Word, ein Browser oder ein unbekanntes Programm ausgeloest hat.
/// </summary>
public static class Provenance
{
    public const string SysmonLog = "Microsoft-Windows-Sysmon/Operational";
    private const int MaxDepth = 8;

    /// <summary>Terminals, Editoren und KI-Werkzeuge, aus denen Entwickler bewusst Befehle starten.</summary>
    private static readonly HashSet<string> TrustedLaunchers = new(StringComparer.OrdinalIgnoreCase)
    {
        "WindowsTerminal.exe", "OpenConsole.exe", "Code.exe", "Code - Insiders.exe", "VSCodium.exe", "Cursor.exe", "Windsurf.exe",
        "devenv.exe", "idea64.exe", "pycharm64.exe", "rider64.exe", "webstorm64.exe", "clion64.exe", "goland64.exe", "phpstorm64.exe",
        "datagrip64.exe", "rustrover64.exe", "Zed.exe", "claude.exe", "Claude.exe", "wezterm-gui.exe", "alacritty.exe", "mintty.exe",
        "ConEmu64.exe", "ConEmu.exe", "Tabby.exe", "Hyper.exe", "warp.exe", "GitHubDesktop.exe", "sublime_text.exe", "notepad++.exe",
    };

    /// <summary>Zwischenglieder, die ein vertrauenswuerdiger Starter typischerweise benutzt.</summary>
    private static readonly HashSet<string> Intermediates = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "bash.exe", "sh.exe", "wsl.exe", "node.exe", "python.exe", "python3.exe", "py.exe",
        "git.exe", "conhost.exe", "dotnet.exe", "npm.exe", "npx.exe", "bun.exe", "deno.exe", "uv.exe", "make.exe", "msbuild.exe",
    };

    /// <summary>Wenn diese Programme eine Shell starten, ist das ein klassisches Angriffsmuster (Phishing-Anhang, Drive-by).</summary>
    private static readonly Dictionary<string, string> SuspiciousParents = new(StringComparer.OrdinalIgnoreCase)
    {
        ["winword.exe"] = "Word", ["excel.exe"] = "Excel", ["powerpnt.exe"] = "PowerPoint", ["outlook.exe"] = "Outlook",
        ["onenote.exe"] = "OneNote", ["msaccess.exe"] = "Access", ["mspub.exe"] = "Publisher", ["acrord32.exe"] = "Adobe Reader",
        ["acrobat.exe"] = "Adobe Acrobat", ["mshta.exe"] = "eine HTA-Datei (mshta)", ["wscript.exe"] = "ein VBS/JS-Skript (wscript)",
        ["cscript.exe"] = "ein VBS/JS-Skript (cscript)", ["hh.exe"] = "eine Hilfedatei (.chm)", ["chrome.exe"] = "den Browser (Chrome)",
        ["msedge.exe"] = "den Browser (Edge)", ["firefox.exe"] = "den Browser (Firefox)", ["brave.exe"] = "den Browser (Brave)",
        ["opera.exe"] = "den Browser (Opera)", ["regsvr32.exe"] = "regsvr32", ["rundll32.exe"] = "rundll32", ["wmiprvse.exe"] = "WMI (Fernsteuerung)",
    };

    public static bool SysmonAvailable()
    {
        try
        {
            using var r = new EventLogReader(new EventLogQuery(SysmonLog, PathType.LogName, "*[System[EventID=1]]"));
            using var e = r.ReadEvent();
            return e != null;
        }
        catch { return false; }
    }

    /// <summary>Startkette des Prozesses <paramref name="pid"/>, der zum Zeitpunkt <paramref name="when"/> lief.</summary>
    public static ProcessChain? Lookup(int pid, DateTime when) => FromSysmon(pid, when) ?? FromSecurityLog(pid, when);

    // ------------------------------------------------------------------
    // Klassifikation (rein, testbar)
    // ------------------------------------------------------------------

    public static OriginVerdict Classify(ProcessChain chain, Func<string, FileTrustInfo> trust)
    {
        var ancestors = chain.Nodes.Skip(1).ToList();
        if (ancestors.Count == 0) return new(OriginKind.Unknown, "Startprogramm unbekannt", null);

        foreach (var node in ancestors)
        {
            if (SuspiciousParents.TryGetValue(node.Name, out var what))
                return new(OriginKind.Suspicious, $"Gestartet über {what} – so laufen Angriffe über Dokumente, Webseiten oder Anhänge ab", node);

            var info = trust(node.Image);
            bool userWritable = LocationClassifierPaths.IsRisky(node.Image);
            if (info.Exists && info.Signature != SignatureState.Valid && userWritable)
                return new(OriginKind.Suspicious, $"Gestartet von einem unsignierten Programm aus einem Benutzerordner ({node.Image})", node);

            if (TrustedLaunchers.Contains(node.Name))
            {
                if (info.Signature == SignatureState.Valid && !LocationClassifierPaths.IsTemp(node.Image))
                    return new(OriginKind.Trusted, $"Aus Ihrem Terminal bzw. Editor gestartet ({node.Name}, signiert von {info.SignerOrganization ?? info.Signer})", node);
                return new(OriginKind.Unknown, $"{node.Name} hat keine gültige Signatur – Herkunft nicht bestätigt", node);
            }

            if (node.Name.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                return new(OriginKind.RunDialog, "Direkt aus Windows gestartet (Startmenü, Doppelklick oder Ausführen-Dialog Win+R)", node);

            if (node.Name is "svchost.exe" or "services.exe" or "taskeng.exe" or "taskhostw.exe" or "wininit.exe")
                return new(OriginKind.Unknown, "Von Windows gestartet (geplante Aufgabe oder Dienst)", node);

            if (!Intermediates.Contains(node.Name))
                return new(OriginKind.Unknown, $"Gestartet von {node.Name}", node);
        }
        return new(OriginKind.Unknown, "Startkette unvollständig", ancestors.Last());
    }

    /// <summary>Haengt die Herkunft als Indikator und Detail an einen Fund.</summary>
    public static OriginVerdict? Annotate(Finding f, int? pid, DateTime when)
    {
        if (pid is not > 0) return null;
        var chain = Lookup(pid.Value, when);
        if (chain == null)
        {
            f.Detail("Gestartet von", "unbekannt – Programmstarts werden nicht aufgezeichnet (Schutz-Assistent → Aufzeichnung)");
            return null;
        }
        var v = Classify(chain, FileTrustService.Shared.Get);
        f.Detail("Gestartet von", $"{chain.Describe()} ({chain.Source})")
         .Detail("Herkunft", v.Reason);
        var cmd = chain.Nodes.Skip(1).FirstOrDefault()?.CommandLine;
        if (!string.IsNullOrEmpty(cmd)) f.Detail("Befehl des Startprogramms", TextUtil.Truncate(cmd, 500));
        switch (v.Kind)
        {
            case OriginKind.Trusted: f.AddIndicator("PS_ORIGIN_TRUSTED", v.Reason, -15); break;
            case OriginKind.Suspicious: f.AddIndicator("PS_ORIGIN_SUSPICIOUS", v.Reason, 50); break;
            case OriginKind.RunDialog: f.AddIndicator("PS_ORIGIN_EXPLORER", v.Reason, 5); break;
        }
        return v;
    }

    // ------------------------------------------------------------------
    // Quellen
    // ------------------------------------------------------------------

    private static ProcessChain? FromSysmon(int pid, DateTime when)
    {
        var first = QueryOne(SysmonLog, $"*[System[EventID=1 and {Before(when)}] and EventData[Data[@Name='ProcessId']='{pid}']]");
        if (first == null) return null;
        var nodes = new List<ProcessNode> { SysmonNode(first) };
        var current = first;
        for (int i = 0; i < MaxDepth; i++)
        {
            var parentGuid = current.GetValueOrDefault("ParentProcessGuid");
            var parent = string.IsNullOrEmpty(parentGuid) ? null
                : QueryOne(SysmonLog, $"*[System[EventID=1] and EventData[Data[@Name='ProcessGuid']='{parentGuid}']]");
            if (parent == null)
            {
                // Eltern-Prozess lief schon vor der Aufzeichnung: Angaben aus dem Kind-Ereignis uebernehmen.
                if (current.TryGetValue("ParentImage", out var img) && !string.IsNullOrEmpty(img) && img != "-")
                    nodes.Add(new ProcessNode(img, current.GetValueOrDefault("ParentCommandLine"), ParseInt(current.GetValueOrDefault("ParentProcessId")), null));
                break;
            }
            nodes.Add(SysmonNode(parent));
            current = parent;
        }
        return new ProcessChain(nodes, "Sysmon");
    }

    private static ProcessNode SysmonNode(Dictionary<string, string> d) => new(
        d.GetValueOrDefault("Image") ?? "?", d.GetValueOrDefault("CommandLine"), ParseInt(d.GetValueOrDefault("ProcessId")),
        DateTime.TryParse(d.GetValueOrDefault("UtcTime"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t) ? t.ToLocalTime() : null);

    private static ProcessChain? FromSecurityLog(int pid, DateTime when)
    {
        var nodes = new List<ProcessNode>();
        int current = pid;
        DateTime t = when;
        for (int i = 0; i <= MaxDepth && current > 0; i++)
        {
            var e = QueryOne("Security", $"*[System[EventID=4688 and {Before(t)}] and EventData[Data[@Name='NewProcessId']='0x{current:x}']]");
            if (e == null) break;
            var started = e.TryGetValue("__Time", out var ts) && DateTime.TryParse(ts, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var st) ? st.ToLocalTime() : (DateTime?)null;
            nodes.Add(new ProcessNode(e.GetValueOrDefault("NewProcessName") ?? "?", e.GetValueOrDefault("CommandLine"), current, started));
            int parentPid = ParseHex(e.GetValueOrDefault("ProcessId"));
            // Eltern-Prozess, der vor der Aufzeichnung startete: wenigstens den Namen festhalten.
            string? parentImage = e.GetValueOrDefault("ParentProcessName");
            var parentEvent = parentPid > 0 ? QueryOne("Security", $"*[System[EventID=4688 and {Before(started ?? t)}] and EventData[Data[@Name='NewProcessId']='0x{parentPid:x}']]") : null;
            if (parentEvent == null)
            {
                if (!string.IsNullOrEmpty(parentImage)) nodes.Add(new ProcessNode(parentImage, null, parentPid, null));
                break;
            }
            current = parentPid;
            t = started ?? t;
        }
        return nodes.Count == 0 ? null : new ProcessChain(nodes, "Windows-Sicherheitsprotokoll");
    }

    private static string Before(DateTime when) =>
        $"TimeCreated[@SystemTime<='{when.ToUniversalTime().AddSeconds(2):yyyy-MM-ddTHH:mm:ss.fffZ}']";

    /// <summary>Neuestes passendes Ereignis als Feld-Woerterbuch (sofort ausgelesen – Records werden danach freigegeben).</summary>
    private static Dictionary<string, string>? QueryOne(string log, string xpath)
    {
        try
        {
            using var reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = true });
            using var rec = reader.ReadEvent();
            if (rec == null) return null;
            var doc = XDocument.Parse(rec.ToXml());
            XNamespace ns = doc.Root!.Name.Namespace;
            var d = doc.Descendants(ns + "Data")
                .Where(x => x.Attribute("Name") != null)
                .GroupBy(x => x.Attribute("Name")!.Value)
                .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);
            d["__Time"] = rec.TimeCreated?.ToUniversalTime().ToString("o") ?? "";
            return d;
        }
        catch { return null; }
    }

    private static int ParseInt(string? s) => int.TryParse(s, out int v) ? v : 0;

    private static int ParseHex(string? s) =>
        s != null && s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && int.TryParse(s[2..], NumberStyles.HexNumber, null, out int v) ? v : ParseInt(s);
}

/// <summary>Einfache Pfad-Einordnung fuer die Herkunftspruefung.</summary>
internal static class LocationClassifierPaths
{
    public static bool IsTemp(string path) =>
        path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase);

    public static bool IsRisky(string path) =>
        IsTemp(path) || path.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\Users\Public\", StringComparison.OrdinalIgnoreCase)
        || (path.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase) && !path.Contains(@"\AppData\Local\Programs\", StringComparison.OrdinalIgnoreCase)
            && !path.Contains(@"\AppData\Local\Microsoft\WindowsApps\", StringComparison.OrdinalIgnoreCase));
}
