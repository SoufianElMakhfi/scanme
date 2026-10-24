namespace ScanMe.Core.Knowledge;

/// <summary>
/// Bekannte Programme, die keine Malware im engeren Sinn sind, aber bei Angriffen und Betrug
/// eine grosse Rolle spielen: Fernwartung (Tech-Support-Scams!), Hacktools, Krypto-Miner.
/// </summary>
public static class KnownTools
{
    public enum ToolKind { RemoteAccess, HackTool, Miner, Tunnel }

    public sealed record Tool(string Name, ToolKind Kind, string[] ProcessNames, string Note);

    public static readonly IReadOnlyList<Tool> All =
    [
        new("AnyDesk", ToolKind.RemoteAccess, ["anydesk.exe"], "Häufig bei Telefonbetrug (falscher Microsoft-/Bank-Support) eingesetzt."),
        new("TeamViewer", ToolKind.RemoteAccess, ["teamviewer.exe", "teamviewer_service.exe", "tv_w32.exe", "tv_x64.exe"], "Legitim, aber häufig bei Support-Betrug missbraucht."),
        new("UltraViewer", ToolKind.RemoteAccess, ["ultraviewer.exe", "ultraviewer_desktop.exe", "ultraviewer_service.exe"], "Häufig bei Support-Betrug eingesetzt."),
        new("ScreenConnect / ConnectWise Control", ToolKind.RemoteAccess, ["screenconnect.clientservice.exe", "screenconnect.windowsclient.exe", "connectwisecontrol.client.exe"], "Wird massiv von Betrügern und Ransomware-Gruppen missbraucht."),
        new("Atera Agent", ToolKind.RemoteAccess, ["ateraagent.exe"], "Fernwartungsagent – oft von Angreifern als Hintertür installiert."),
        new("Splashtop", ToolKind.RemoteAccess, ["srservice.exe", "strwinclt.exe", "splashtop.exe"], "Fernwartung."),
        new("RustDesk", ToolKind.RemoteAccess, ["rustdesk.exe"], "Open-Source-Fernwartung, zunehmend bei Betrug genutzt."),
        new("NetSupport Manager", ToolKind.RemoteAccess, ["client32.exe"], "Wird als 'NetSupport RAT' in Phishing-Kampagnen verbreitet."),
        new("Ammyy Admin", ToolKind.RemoteAccess, ["aa_v3.exe", "ammyy_admin.exe"], "Bekannt aus Betrugsmaschen."),
        new("Supremo", ToolKind.RemoteAccess, ["supremo.exe", "supremoservice.exe"], "Fernwartung, bei Betrug genutzt."),
        new("LogMeIn", ToolKind.RemoteAccess, ["logmein.exe", "lmiguardiansvc.exe"], "Fernwartung."),
        new("Remote Utilities", ToolKind.RemoteAccess, ["rutserv.exe", "rfusclient.exe"], "Häufig als RAT missbraucht."),
        new("SimpleHelp", ToolKind.RemoteAccess, ["remote access.exe", "simplehelp.exe", "simpleservice.exe"], "Von Angreifern genutzte Fernwartung."),
        new("MeshCentral Agent", ToolKind.RemoteAccess, ["meshagent.exe"], "Open-Source-Fernwartungsagent, von Angreifern genutzt."),
        new("Chrome Remote Desktop", ToolKind.RemoteAccess, ["remoting_host.exe"], "Fernzugriff über Google-Konto."),
        new("Quick Assist", ToolKind.RemoteAccess, ["quickassist.exe"], "Windows-Bordmittel, wird bei Support-Betrug missbraucht."),

        new("Mimikatz", ToolKind.HackTool, ["mimikatz.exe", "mimi.exe"], "Werkzeug zum Auslesen von Passwörtern."),
        new("Netcat", ToolKind.HackTool, ["nc.exe", "nc64.exe", "ncat.exe"], "Netzwerk-Werkzeug, oft für Reverse Shells genutzt."),
        new("PsExec", ToolKind.HackTool, ["psexec.exe", "psexec64.exe", "psexesvc.exe", "paexec.exe"], "Fernausführung – legitim für Admins, aber typisch für laterale Bewegung."),
        new("ProcDump", ToolKind.HackTool, ["procdump.exe", "procdump64.exe"], "Kann zum Auslesen von LSASS missbraucht werden."),
        new("Rubeus / SharpHound / Seatbelt", ToolKind.HackTool, ["rubeus.exe", "sharphound.exe", "seatbelt.exe", "winpeas.exe", "winpeasx64.exe", "lazagne.exe", "sharpup.exe"], "Bekannte Angriffs- und Aufklärungswerkzeuge."),
        new("Cobalt Strike Beacon (typische Namen)", ToolKind.HackTool, ["beacon.exe", "artifact.exe", "artifact64.exe"], "Typische Standardnamen von Cobalt-Strike-Payloads."),

        new("XMRig", ToolKind.Miner, ["xmrig.exe", "xmrig-notls.exe"], "Krypto-Miner – oft heimlich installiert, verbraucht Strom und CPU."),
        new("Weitere Miner", ToolKind.Miner, ["nbminer.exe", "t-rex.exe", "phoenixminer.exe", "lolminer.exe", "gminer.exe", "ethminer.exe", "nanominer.exe", "cpuminer.exe", "minerd.exe"], "Krypto-Miner."),

        new("ngrok / Tunnel", ToolKind.Tunnel, ["ngrok.exe", "cloudflared.exe", "chisel.exe", "plink.exe", "frpc.exe"], "Tunnel-Software – kann den PC von aussen erreichbar machen."),
    ];

    private static readonly Dictionary<string, Tool> ByProcess = All
        .SelectMany(t => t.ProcessNames.Select(p => (p, t)))
        .GroupBy(x => x.p, StringComparer.OrdinalIgnoreCase)
        .ToDictionary(g => g.Key, g => g.First().t, StringComparer.OrdinalIgnoreCase);

    public static Tool? FindByProcessName(string name) =>
        ByProcess.TryGetValue(name, out var t) ? t
            : Updates.RuleStore.KnownTools.FirstOrDefault(x => x.ProcessNames.Contains(name, StringComparer.OrdinalIgnoreCase));

    /// <summary>Sucht anhand des Anzeigenamens installierter Software (voller Toolname, z. B. "Chrome Remote Desktop").</summary>
    public static Tool? FindByDisplayName(string displayName) =>
        All.Concat(Updates.RuleStore.KnownTools)
           .FirstOrDefault(t => t.Name.Split(" / ").Any(alt => displayName.Contains(alt.Trim(), StringComparison.OrdinalIgnoreCase)));

    public static string KindText(ToolKind k) => k switch
    {
        ToolKind.RemoteAccess => "Fernwartungssoftware",
        ToolKind.HackTool => "Hacking-Werkzeug",
        ToolKind.Miner => "Krypto-Miner",
        ToolKind.Tunnel => "Tunnel-Software",
        _ => k.ToString(),
    };
}
