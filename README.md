# ScanMe – Blue Team PC-Scanner für Windows 10/11

ScanMe durchleuchtet einen Windows-PC so, wie es ein Sicherheitsanalyst (Blue Team) tun würde:
Was läuft wirklich? Was startet automatisch? Wohin wird kommuniziert? Gibt es Spuren eines
früheren Angriffs oder Phishings? Zu **jedem Fund** erklärt ScanMe, *was* gefunden wurde,
*warum* es relevant ist und *was zu tun ist*, mit allen Beweisen (Indikatoren) und gewichtetem Risiko-Score.

> **Grundsatz:** Windows-Komponenten werden **niemals** gelöscht oder beendet. Jede Aktion wird vor der
> Ausführung erneut geprüft und lässt sich (bis auf das Entfernen von WMI-Abonnements) rückgängig machen.

## Download & Start

1. Unter **Releases** die Datei `ScanMe-win-x64.zip` herunterladen (ARM64 für Snapdragon-/Surface-Geräte).
2. Entpacken und `ScanMe.exe` starten – **keine Installation, kein .NET nötig**. Den Ordner `Data` (Treiberliste)
   neben der EXE lassen.
3. Die App fragt nach Administratorrechten. Ohne sie fehlen u. a. fremde Prozesse, das Sicherheitsprotokoll,
   Defender-Ausnahmen und viele geplante Aufgaben.

Läuft auf **Windows 10 (ab 1809) und Windows 11**, x64 und ARM64.

> **SmartScreen-Warnung beim ersten Start:** ScanMe ist (noch) nicht mit einem kostenpflichtigen
> Code-Signing-Zertifikat signiert. Windows zeigt daher „Der Computer wurde durch Windows geschützt“.
> Prüfe die Prüfsumme der ZIP mit `SHA256SUMS.txt` aus dem Release und wähle dann
> „Weitere Informationen → Trotzdem ausführen“.

## Updates

- **Programm:** ScanMe prüft beim Start, ob es eine neuere Version gibt, und bietet sie an. Ein Klick lädt das
  Update, prüft es, tauscht die Dateien aus und startet ScanMe neu. Quarantäne, Verlauf, Ignorierliste und
  Einstellungen liegen in `C:\ProgramData\ScanMe` und bleiben erhalten. Per Kommandozeile: `scanme-cli --self-update`.
  - Geprüft wird vor dem Austausch: die **SHA256-Prüfsumme** aus dem Release, dass die Version **neuer** ist
    (kein Zurückspielen alter Versionen) und – sobald ScanMe signiert ist – dass die neue Version **vom selben
    Herausgeber signiert** ist. Erst die Signatur schützt auch vor einem übernommenen GitHub-Konto.
  - Bei einem Fehler wird alles zurückgerollt. Bewusst **kein Zwangs-Update**: ScanMe muss auch offline
    funktionieren, etwa wenn der PC nach einem Befall vom Netz getrennt ist.
  - Hat eine Version einen bekannten schweren Fehler, warnt ScanMe über das signierte Regelpaket deutlich davor.
- **Erkennungsregeln:** Vor jedem Scan lädt ScanMe neue Regeln aus [`rules/rules.json`](rules/rules.json).
  Sie werden **nur übernommen, wenn ihre digitale Signatur (ECDSA P-256) gültig ist** – selbst ein
  übernommenes GitHub-Konto könnte keine manipulierten Regeln verteilen. Online-Regeln können Erkennungen
  nur **ergänzen**, niemals eingebaute Regeln entfernen oder abschwächen. Ohne Internet arbeitet ScanMe
  mit den zuletzt geprüften bzw. eingebauten Regeln.

## Datenschutz

ScanMe sendet **keine Daten von deinem PC** irgendwohin. Es gibt genau drei Netzwerkzugriffe:

| Zugriff | Wann | Was wird übertragen |
|---|---|---|
| `api.github.com` (neueste Version) | beim Start | nur die Anfrage selbst (IP-Adresse, „ScanMe/Version“) |
| `raw.githubusercontent.com` (Regeln) | vor jedem Scan | nur die Anfrage selbst |
| VirusTotal | nur wenn du „Auf VirusTotal prüfen“ klickst | der SHA256-Hash der Datei (öffnet sich im Browser), **nie die Datei** |

Die ersten beiden lassen sich unter *Einstellungen → Online-Funktionen* abschalten.
Der installierte Virenschutz wird lokal befragt: Microsoft Defender über `MpCmdRun.exe`, andere Virenschutzprogramme
über die Windows-Schnittstelle AMSI. Deren eigene Cloud-Einstellungen gelten unverändert. Abschaltbar unter
*Einstellungen → Scan* bzw. mit `--no-defender`.

## Was wird geprüft?

| Bereich | Inhalt |
|---|---|
| **Prozesse** | Prozessliste aus 4 Quellen (Kernel, PSAPI, WMI, PID-Bruteforce) → **versteckte Prozesse/Rootkits**; Tarnung als Systemprozess (falscher Pfad/Elternprozess, `scvhost.exe`), mehrfaches `lsass.exe`, **Office/PDF/Mail startet PowerShell** (Phishing), gelöschte Programmdatei bei laufendem Prozess, unsichtbare Hintergrundprozesse, CPU-/RAM-Fresser, Bloatware & PUPs |
| **Autostart & Persistenz** | Run/RunOnce (alle Benutzer, 32/64 Bit), Autostart-Ordner, **geplante Aufgaben inkl. versteckter Tasks (Tarrask)**, Dienste, **WMI-Event-Abonnements**, Winlogon, IFEO-Debugger, AppInit/AppCert-DLLs, LSA-Pakete, BootExecute, cmd-AutoRun, Netsh-Helper, **Bedienungshilfen-Hintertür** (sethc/utilman), PowerShell-Profile |
| **Netzwerk** | Verbindungen pro Prozess, offene Ports, RAT-/Tor-/Mining-Ports, **Hosts-Datei-Manipulation**, Proxy/PAC-Umleitung, DNS, **MITM-Stammzertifikate** |
| **Malware** | Defender-Bedrohungsverlauf (auch frühere/entfernte Funde), **Inhaltssignaturen** (Infostealer, RATs, Mimikatz, Cobalt Strike, Miner, Keylogger, Tor-C2, Discord/Telegram-Exfiltration), Packer/Entropie, gefälschte Microsoft-Metadaten, **rund 4.700 YARA-Regeln** von Sicherheitsfirmen und -forschern (ESET, Mandiant, Google, Volexity, Malpedia, Signature Base u. a., über [YARA Forge](https://github.com/YARAHQ/yara-forge), ausgeführt mit [YARA-X](https://github.com/VirusTotal/yara-x)) für alle auffälligen Dateien und laufenden Programme, **der installierte Virenschutz**: Microsoft Defender prüft zuerst in Downloads, Desktop, Public und Temp alle Programme, Installer, Archive (inkl. Inhalt), Skripte, Verknüpfungen und Dokumente einzeln (neueste zuerst; Schnellscan mit 3 Minuten Zeitbudget). Der **vollständige Scan** hat keine Zeit- oder Größenlimits und lässt Defender danach **jedes interne Laufwerk komplett und den Bootsektor** prüfen – ohne etwas zu entfernen, das kann Stunden dauern; über **AMSI** werden alle auffälligen Dateien und laufenden Programme dem installierten Virenschutz vorgelegt (Defender, aber auch Avast, ESET, Kaspersky u. a.) – damit fließen dessen Signaturen und Cloud-Erkennung ein |
| **Dateisystem & Phishing** | Downloads, Desktop, AppData, Temp, Public, ProgramData, Papierkorb: versteckte Programme, Doppelendungen (`rechnung.pdf.exe`), RTLO-Tricks, **LNK-Phishing**, ISO/IMG/VHD-Container, Makro-Dokumente/OneNote, **versteckte NTFS-Datenströme**, Ransomware-Notizen/-Endungen, **Download-Quelle (URL) jeder Datei** |
| **Browser** | Erweiterungen (Chrome, Edge, Brave, Vivaldi, Opera, Firefox) mit Rechten & Herkunft, **per Richtlinie erzwungene Erweiterungen**, Startseiten-/Such-Hijacking, **Benachrichtigungs-Spam**, manipulierte Browser-Verknüpfungen |
| **Treiber** | Abgleich aller Treiber mit **rund 700 bekannt verwundbaren und bösartigen Treibern** aus [LOLDrivers](https://www.loldrivers.io) – über den Fingerabdruck (SHA256 und Authentihash), daher auch umbenannt oder neu signiert erkannt; unsignierte und **umbenannte Treiber** (z. B. WinRing0 von Krypto-Minern), Testsignaturmodus, Treiber-Sperrliste, Speicherintegrität |
| **Ereignisprotokolle** | Gelöschte Logs, neu installierte Dienste, neue Konten/Admins, **Brute-Force**, **RDP-Anmeldungen aus dem Internet**, Defender-Ausnahmen, von PowerShell markierte Skripte |
| **Sicherheitseinstellungen** | Defender (Echtzeitschutz, Signaturen, Manipulationsschutz, **Ausnahmen**), Firewall, UAC, SmartScreen, WDigest, LSA-Schutz, RDP/NLA, SMBv1, Updates, Secure Boot, Auto-Login-Passwort |
| **Konten** | Versteckte Konten (`$`, vom Anmeldebildschirm ausgeblendet), Gast/Admin aktiv, neue Admins |
| **Software** | PUPs, Fernwartungstools (AnyDesk, TeamViewer … – Telefonbetrug!), Installations-Zeitleiste, **Versionen mit aktiv ausgenutzten Lücken** (WinRAR, 7-Zip, Flash, Java …) |
| **Kompatibilität** | Geräte-/Treiberfehler, Bluescreens, abstürzende Programme inkl. verursachender DLL, Speicherplatz, SMART-Warnungen, mehrere Virenscanner gleichzeitig |

### Zeitleiste
Alle Funde in der Reihenfolge, in der sie **passiert** sind: Datei heruntergeladen, Dienst installiert, Aufgabe angelegt,
PowerShell-Skript ausgeführt, Defender-Fund, Konto angelegt … Mehrere auffällige Ereignisse innerhalb weniger Minuten
werden als **Häufung** markiert – so wird der Ablauf eines Angriffs sichtbar (z. B. Download → Ausführen → Autostart).
Die Zeitleiste steht auch im exportierten HTML-Bericht.

### Echtzeitüberwachung
Neue Prozesse, Autostarts, Dateien (Downloads/Temp/AppData/Autostart), Netzwerkverbindungen unsignierter
Programme und Änderungen der Hosts-Datei werden **sofort** bewertet. Warnungen erscheinen als
Windows-Benachrichtigung; ScanMe läuft dann im Infobereich weiter.

### Gegenmaßnahmen (alle mit Bestätigung)
Prozess beenden · Datei in **Quarantäne** (verschlüsselt, wiederherstellbar; gesperrte Dateien beim Neustart) ·
Autostart deaktivieren (wie im Task-Manager) · Aufgabe/Dienst deaktivieren · Registry-Wert entfernen bzw. auf
Windows-Standard setzen · WMI-Abonnement entfernen · Defender-Ausnahme entfernen · Hosts-Datei zurücksetzen ·
Datei mit Defender scannen · Hash auf VirusTotal nachschlagen (es wird **nur der Hash** übertragen) · Ignorieren.

Alles Geänderte steht unter **Quarantäne & Verlauf** und lässt sich dort rückgängig machen.

### Sicherheitsgarantien (automatisch getestet)
`SafetyGuard` prüft jede Aktion unmittelbar vor der Ausführung, unabhängig vom Scanergebnis:
- keine Quarantäne für Microsoft-signierte Dateien und Dateien im Windows-Verzeichnis
- kein Beenden kritischer Prozesse (`lsass`, `csrss`, `wininit`, `services`, `smss`, `svchost` …), sofern es die echten sind
- kein Deaktivieren von Windows-Kerndiensten (RPC, Defender, Firewall, Event Log …)
- LSA-/Winlogon-Werte werden nie gelöscht, nur gezielt auf den Standard gesetzt
- der Datenordner `C:\ProgramData\ScanMe` ist nur für SYSTEM und Administratoren beschreibbar. Einträge, die nicht
  von ihnen stammen (oder Links sind), legt ScanMe beim Start beiseite und verwendet sie nie. Ohne Adminrechte
  nutzt ScanMe einen eigenen Ordner pro Benutzer (`%LOCALAPPDATA%\ScanMe`).

## Kommandozeile

```powershell
scanme-cli.exe                     # Vollständiger Scan
scanme-cli.exe --quick             # Schnellscan
scanme-cli.exe --only processes,network --all
scanme-cli.exe --json bericht.json
scanme-cli.exe --monitor 300       # 5 Minuten Echtzeitüberwachung
scanme-cli.exe --help              # alle Scanner-IDs
```
Exit-Code: `2` = kritische Funde, `1` = hohe Funde, `3` = Scan unvollständig (abgebrochen oder Scannerfehler),
`4` = falscher Aufruf (unbekannte Option oder Scanner-ID), `0` = sonst. Ein unvollständiger Scan liefert nie `0`.

## Selbst bauen

Voraussetzung: [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0). Visual Studio 2022 oder VS Code sind optional.

```powershell
dotnet build ScanMe.sln
dotnet test tests/ScanMe.Tests
powershell -ExecutionPolicy Bypass -File publish.ps1      # -> publish\win-x64\ScanMe.exe
```

Ein Push auf `main` baut und testet automatisch (GitHub Actions). Ein Tag `v*` (z. B. `v1.0.0`) erzeugt ein
Release mit fertigen ZIPs für x64 und ARM64.

## Projektstruktur

```
src/ScanMe.Core     Engine: Scanner, Bewertung, Signaturprüfung, Monitor, Aktionen, Berichte
  Scanners/         Prozesse, Persistenz, Netzwerk, Sicherheit, Konten, Software, Browser,
                    Treiber, Ereignisprotokolle, Kompatibilität, Dateisystem, Malware
  Knowledge/        Wissensbasis: Systemprozesse, Kommandozeilen-Regeln (MITRE ATT&CK),
                    Inhaltssignaturen, Fernwartungs-/Hacktools, PUP-Katalog
  Engine/           ScanEngine, RiskScorer, ExecutableAssessor, StaticAnalyzer
  Trust/            Authenticode + Windows-Katalog + MSIX-Paketsignaturen, Mark of the Web
  Actions/          SafetyGuard, Quarantäne, Rückgängig-Journal, Ignorierliste
  Monitoring/       Echtzeitüberwachung
src/ScanMe.App      WPF-Oberfläche (MVVM)
src/ScanMe.Cli      Kommandozeile
tests/ScanMe.Tests  xUnit: Sicherheitszusagen und Erkennungsregeln
```

## Wie bewertet ScanMe?

Jeder Fund sammelt **Indikatoren** mit Gewicht (z. B. `+50 Name ahmt svchost.exe nach`,
`−40 gültig von Microsoft signiert`). Die Summe (0–100) ergibt den Schweregrad:
**Kritisch** ≥ 80 · **Hoch** ≥ 60 · **Mittel** ≥ 35 · **Niedrig** ≥ 15 · sonst **Info**.
Verifizierte Windows-Komponenten werden gedeckelt, außer es liegt ein harter Missbrauchsindikator vor
(z. B. eine verschleierte PowerShell-Kommandozeile – Windows-Werkzeuge wie PowerShell selbst sind harmlos,
bewertet wird, *was* sie ausführen).

## Grenzen

ScanMe ergänzt einen Virenscanner, ersetzt ihn aber nicht. Die Heuristiken sind auf wenige Fehlalarme
abgestimmt, können aber nicht jede Malware erkennen – insbesondere keine Kernel-Rootkits, die sich vor
allen Windows-Schnittstellen verbergen. Bei kritischen Funden zusätzlich einen
**Microsoft Defender Offline-Scan** ausführen (Windows-Sicherheit → Viren- & Bedrohungsschutz → Scanoptionen).
YARA gibt es nur in der x64-Version: Für Windows auf ARM stellt YARA-X (noch) keine Bibliothek bereit.
Berichte enthalten Pfade und Benutzernamen – nur an vertrauenswürdige Personen weitergeben.

## Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

> **Status:** Die Aufnahme ins Programm der SignPath Foundation ist beantragt. Bis zur Freigabe sind Releases
> noch unsigniert – prüfe sie über `SHA256SUMS.txt`.

- Signiert werden ausschließlich `ScanMe.exe` und `scanme-cli.exe`, die GitHub Actions aus diesem Repository baut
  ([Workflow](.github/workflows/build.yml)). Lokal gebaute Dateien werden nie signiert.
- Jede Signieranfrage wird einzeln von einem Approver freigegeben, nur für Releases (Git-Tags `v*`).
- Rollen:
  - Committer und Reviewer: [Soufian El Makhfi](https://github.com/SoufianElMakhfi)
  - Approver: [Soufian El Makhfi](https://github.com/SoufianElMakhfi)
- Alle Beteiligten nutzen Zwei-Faktor-Authentifizierung für GitHub und SignPath.
- Datenschutz: ScanMe überträgt keine Daten von deinem PC. Welche Netzwerkzugriffe es gibt und wie man sie
  abschaltet, steht unter [Datenschutz](#datenschutz).

Eine signierte Datei erkennst du unter *Eigenschaften → Digitale Signaturen*: Signaturgeber ist „SignPath Foundation“.

## Mitwirken

Fehlalarme, übersehene Malware, neue Regeln und Code-Beiträge sind willkommen – siehe
[CONTRIBUTING.md](CONTRIBUTING.md). Sicherheitslücken in ScanMe bitte privat melden: [SECURITY.md](SECURITY.md).

## Lizenz und Haftungsausschluss

ScanMe ist freie Software unter der **GNU General Public License v3.0** – siehe [LICENSE](LICENSE).
Du darfst ScanMe nutzen, verändern und weitergeben; veränderte Versionen müssen ebenfalls unter der GPL-3.0
mit Quellcode veröffentlicht werden.

**ScanMe wird ohne jede Gewährleistung bereitgestellt** (GPL-3.0, Abschnitte 15 und 16). ScanMe arbeitet
mit Heuristiken und kann Schadsoftware übersehen oder harmlose Programme als verdächtig melden. Jede Aktion
(Beenden, Quarantäne, Deaktivieren) wird von dir ausgelöst und bestätigt; prüfe Funde vor dem Handeln und
sichere wichtige Daten. Die Nutzung erfolgt auf eigene Verantwortung; eine Haftung der Autoren ist
ausgeschlossen, soweit gesetzlich zulässig.

Copyright © 2026 Soufian El Makhfi und Mitwirkende.
