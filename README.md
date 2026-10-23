# ScanMe – Blue Team PC-Scanner für Windows 10/11

ScanMe durchleuchtet einen Windows-PC so, wie es ein Sicherheitsanalyst (Blue Team) tun würde:
Was läuft wirklich? Was startet automatisch? Wohin wird kommuniziert? Gibt es Spuren eines
früheren Angriffs oder Phishings? Zu **jedem Fund** erklärt ScanMe, *was* gefunden wurde,
*warum* es relevant ist und *was zu tun ist*, mit allen Beweisen (Indikatoren) und gewichtetem Risiko-Score.

> **Grundsatz:** Windows-Komponenten werden **niemals** gelöscht oder beendet. Jede Aktion wird vor der
> Ausführung erneut geprüft und lässt sich (bis auf das Entfernen von WMI-Abonnements) rückgängig machen.

## Download & Start

1. Unter **Releases** die Datei `ScanMe-win-x64.zip` herunterladen (ARM64 für Snapdragon-/Surface-Geräte).
2. Entpacken und `ScanMe.exe` starten – **keine Installation, kein .NET nötig**.
3. Die App fragt nach Administratorrechten. Ohne sie fehlen u. a. fremde Prozesse, das Sicherheitsprotokoll,
   Defender-Ausnahmen und viele geplante Aufgaben.

Läuft auf **Windows 10 (ab 1809) und Windows 11**, x64 und ARM64.

## Was wird geprüft?

| Bereich | Inhalt |
|---|---|
| **Prozesse** | Prozessliste aus 4 Quellen (Kernel, PSAPI, WMI, PID-Bruteforce) → **versteckte Prozesse/Rootkits**; Tarnung als Systemprozess (falscher Pfad/Elternprozess, `scvhost.exe`), mehrfaches `lsass.exe`, **Office/PDF/Mail startet PowerShell** (Phishing), gelöschte Programmdatei bei laufendem Prozess, unsichtbare Hintergrundprozesse, CPU-/RAM-Fresser, Bloatware & PUPs |
| **Autostart & Persistenz** | Run/RunOnce (alle Benutzer, 32/64 Bit), Autostart-Ordner, **geplante Aufgaben inkl. versteckter Tasks (Tarrask)**, Dienste, **WMI-Event-Abonnements**, Winlogon, IFEO-Debugger, AppInit/AppCert-DLLs, LSA-Pakete, BootExecute, cmd-AutoRun, Netsh-Helper, **Bedienungshilfen-Hintertür** (sethc/utilman), PowerShell-Profile |
| **Netzwerk** | Verbindungen pro Prozess, offene Ports, RAT-/Tor-/Mining-Ports, **Hosts-Datei-Manipulation**, Proxy/PAC-Umleitung, DNS, **MITM-Stammzertifikate** |
| **Malware** | Defender-Bedrohungsverlauf (auch frühere/entfernte Funde), **Inhaltssignaturen** (Infostealer, RATs, Mimikatz, Cobalt Strike, Miner, Keylogger, Tor-C2, Discord/Telegram-Exfiltration), Packer/Entropie, gefälschte Microsoft-Metadaten, **Zweitmeinung durch Microsoft Defender** |
| **Dateisystem & Phishing** | Downloads, Desktop, AppData, Temp, Public, ProgramData, Papierkorb: versteckte Programme, Doppelendungen (`rechnung.pdf.exe`), RTLO-Tricks, **LNK-Phishing**, ISO/IMG/VHD-Container, Makro-Dokumente/OneNote, **versteckte NTFS-Datenströme**, Ransomware-Notizen/-Endungen, **Download-Quelle (URL) jeder Datei** |
| **Browser** | Erweiterungen (Chrome, Edge, Brave, Vivaldi, Opera, Firefox) mit Rechten & Herkunft, **per Richtlinie erzwungene Erweiterungen**, Startseiten-/Such-Hijacking, **Benachrichtigungs-Spam**, manipulierte Browser-Verknüpfungen |
| **Treiber** | Unsignierte, **verwundbare (BYOVD)** und **umbenannte Treiber** (z. B. WinRing0 von Krypto-Minern), Testsignaturmodus, Treiber-Sperrliste, Speicherintegrität |
| **Ereignisprotokolle** | Gelöschte Logs, neu installierte Dienste, neue Konten/Admins, **Brute-Force**, **RDP-Anmeldungen aus dem Internet**, Defender-Ausnahmen, von PowerShell markierte Skripte |
| **Sicherheitseinstellungen** | Defender (Echtzeitschutz, Signaturen, Manipulationsschutz, **Ausnahmen**), Firewall, UAC, SmartScreen, WDigest, LSA-Schutz, RDP/NLA, SMBv1, Updates, Secure Boot, Auto-Login-Passwort |
| **Konten** | Versteckte Konten (`$`, vom Anmeldebildschirm ausgeblendet), Gast/Admin aktiv, neue Admins |
| **Software** | PUPs, Fernwartungstools (AnyDesk, TeamViewer … – Telefonbetrug!), Installations-Zeitleiste, **Versionen mit aktiv ausgenutzten Lücken** (WinRAR, 7-Zip, Flash, Java …) |
| **Kompatibilität** | Geräte-/Treiberfehler, Bluescreens, abstürzende Programme inkl. verursachender DLL, Speicherplatz, SMART-Warnungen, mehrere Virenscanner gleichzeitig |

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

## Kommandozeile

```powershell
scanme-cli.exe                     # Vollständiger Scan
scanme-cli.exe --quick             # Schnellscan
scanme-cli.exe --only processes,network --all
scanme-cli.exe --json bericht.json
scanme-cli.exe --monitor 300       # 5 Minuten Echtzeitüberwachung
scanme-cli.exe --help              # alle Scanner-IDs
```
Exit-Code: `2` = kritische Funde, `1` = hohe Funde, `0` = sonst.

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
Berichte enthalten Pfade und Benutzernamen – nur an vertrauenswürdige Personen weitergeben.
