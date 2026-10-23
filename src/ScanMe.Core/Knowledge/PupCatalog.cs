namespace ScanMe.Core.Knowledge;

/// <summary>
/// Unnoetige Hintergrundprogramme (Bloat) und potenziell unerwuenschte Programme (PUPs),
/// die ueber Software-Bundles oder Werbung auf den PC gelangen.
/// </summary>
public static class PupCatalog
{
    public enum Kind
    {
        /// <summary>Harmlos, aber unnoetig im Hintergrund (Updater, Helfer).</summary>
        Bloat,
        /// <summary>Potenziell unerwuenscht: Adware, Browser-Hijacker, Scareware.</summary>
        Pup,
    }

    public sealed record Entry(string Name, Kind Kind, string[] Names, string Advice);

    public static readonly IReadOnlyList<Entry> All =
    [
        // --- Bloat: Updater und Tray-Helfer ---
        new("Google Updater", Kind.Bloat, ["googleupdate.exe", "googlecrashhandler.exe", "googlecrashhandler64.exe", "updater.exe#google"], "Aktualisiert Google-Programme. Kann bleiben – Updates sind wichtig –, muss aber nicht dauerhaft laufen."),
        new("Adobe-Hintergrunddienste", Kind.Bloat, ["adobearm.exe", "adobeupdateservice.exe", "acrotray.exe", "adobecollabsync.exe", "ccxprocess.exe", "adobe desktop service.exe", "adobeipcbroker.exe", "coresync.exe", "agsservice.exe", "adobegcclient.exe"], "Adobe-Hilfsprozesse. Autostart kann in den Adobe-Einstellungen bzw. im Task-Manager (Autostart) deaktiviert werden."),
        new("Java Update Scheduler", Kind.Bloat, ["jusched.exe", "jucheck.exe"], "Java-Updater. Falls Java nicht gebraucht wird: Java deinstallieren."),
        new("Apple-Hilfsprozesse", Kind.Bloat, ["itun_helper.exe", "itunes helper.exe", "ituneshelper.exe", "applemobiledeviceservice.exe", "softwareupdate.exe#apple"], "Nur noetig, wenn ein iPhone per Kabel synchronisiert wird."),
        new("Microsoft Edge Update", Kind.Bloat, ["microsoftedgeupdate.exe"], "Edge-Updater, laeuft periodisch. Unbedenklich."),
        new("CCleaner-Ueberwachung", Kind.Bloat, ["ccleaner64.exe", "ccleaner.exe", "ccleanerbrowser.exe"], "CCleaner-Hintergrundueberwachung ist unnoetig; Windows hat eigene Speicheroptimierung."),
        new("Spiele-Launcher im Autostart", Kind.Bloat, ["epicgameslauncher.exe", "ealauncher.exe", "eadesktop.exe", "origin.exe", "ubisoftconnect.exe", "upc.exe", "battle.net.exe", "galaxyclient.exe", "riotclientservices.exe"], "Launcher muessen nicht mit Windows starten – Autostart im Launcher deaktivieren spart RAM und Bootzeit."),
        new("Dropbox / Cloud-Updater", Kind.Bloat, ["dropboxupdate.exe", "braveupdate.exe", "operagx_assistant.exe", "opera_autoupdate.exe", "browser_assistant.exe"], "Update-Helfer, nicht zwingend noetig."),
        new("Hersteller-Tools", Kind.Bloat, ["hpsupportassistant.exe", "hptouchpointanalyticsclient.exe", "lenovovantageservice.exe", "dellsupportassist.exe", "supportassistagent.exe", "asus_framework.exe", "armourycrate.service.exe", "mcafee webadvisor.exe", "servicehost.exe#mcafee"], "Vorinstallierte Herstellersoftware. Oft unnoetig und mit eigener Telemetrie."),

        // --- PUPs: Adware, Hijacker, Scareware ---
        new("Wave Browser", Kind.Pup, ["wavebrowser.exe", "swupdater.exe", "wavebrowser updater.exe"], "Werbefinanzierter Browser, der sich oft ungefragt installiert und als Standardbrowser setzt. Deinstallieren."),
        new("OneLaunch", Kind.Pup, ["onelaunch.exe", "onelaunchtray.exe", "chromium.exe#onelaunch"], "Adware-Startleiste. Deinstallieren."),
        new("Shift Browser", Kind.Pup, ["shift.exe#shift"], "Wird oft gebuendelt verteilt. Pruefen, ob gewollt."),
        new("Segurazo / SAntivirus", Kind.Pup, ["santivirusservice.exe", "santivirusclient.exe", "segurazo.exe"], "Scareware-'Antivirus'. Deinstallieren."),
        new("ByteFence", Kind.Pup, ["bytefence.exe", "bytefenceservice.exe"], "Gebuendelte Scareware. Deinstallieren."),
        new("Restoro / Reimage", Kind.Pup, ["restoro.exe", "restoroservice.exe", "reimage.exe", "reimagerepair.exe", "fortect.exe"], "Scareware 'PC-Reparatur' – zeigt erfundene Probleme, um ein Abo zu verkaufen. Deinstallieren."),
        new("Driver-Updater-Scareware", Kind.Pup, ["driversupport.exe", "driverupdate.exe", "driverbooster.exe", "driver booster.exe", "drivereasy.exe", "outbytedriverupdater.exe", "pcaccelerate.exe"], "Treiber-'Optimierer' sind unnoetig und teils gefaehrlich – Windows Update liefert Treiber."),
        new("Lavasoft Web Companion", Kind.Pup, ["webcompanion.exe", "adaware web companion.exe"], "Aendert Browser-Startseite/Suche. Deinstallieren."),
        new("PDF-Hijacker", Kind.Pup, ["pdfsuite.exe", "pdfpower.exe", "pdfhub.exe", "pdfconverterhq.exe", "easypdfcombine.exe", "pdfmagic.exe", "manualslib.exe"], "Getarnte 'PDF-Tools', die die Browsersuche umleiten. Deinstallieren."),
        new("Search-Hijacker", Kind.Pup, ["searchbaron.exe", "mysearch.exe", "conduit.exe", "babylon.exe"], "Leitet Suchanfragen um. Deinstallieren."),
        new("KMS-/Crack-Aktivatoren", Kind.Pup, ["kmspico.exe", "kmsauto.exe", "kmsautonet.exe", "autokms.exe", "kmseldi.exe", "aact.exe"], "Illegale Aktivierungstools – enthalten sehr haeufig Malware. Entfernen und System pruefen."),
    ];

    private static readonly Dictionary<string, Entry> ByName = All
        .SelectMany(e => e.Names.Where(n => !n.Contains('#')).Select(n => (n, e)))
        .GroupBy(x => x.n, StringComparer.OrdinalIgnoreCase)
        .ToDictionary(g => g.Key, g => g.First().e, StringComparer.OrdinalIgnoreCase);

    public static Entry? Find(string processName) => ByName.TryGetValue(processName, out var e) ? e : null;

    /// <summary>Sucht nach Programmnamen (z. B. Anzeigename in "Programme und Features").</summary>
    public static Entry? FindByDisplayName(string displayName) =>
        All.FirstOrDefault(e => displayName.Contains(e.Name.Split(' ', '/')[0], StringComparison.OrdinalIgnoreCase) && e.Kind == Kind.Pup);
}
