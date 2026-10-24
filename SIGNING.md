# Code-Signierung einrichten (für Maintainer)

ScanMe wird über die **SignPath Foundation** signiert: kostenlos für Open-Source-Projekte, die Signatur läuft
direkt in GitHub Actions. Das Zertifikat lautet auf „SignPath Foundation“, nicht auf eine Privatperson.
Der private Schlüssel liegt bei SignPath in einem Hardware-Sicherheitsmodul und nie im Repository.

Solange SignPath nicht eingerichtet ist, baut der Workflow wie bisher unsignierte Releases. Der Signierschritt
wird nur aktiv, wenn das Secret `SIGNPATH_API_TOKEN` existiert, und nur bei Tags `v*`.

## 1. Voraussetzungen prüfen

- [ ] Zwei-Faktor-Authentifizierung im GitHub-Konto aktiv
- [ ] Mindestens ein veröffentlichtes Release (gibt es schon)
- [ ] Abschnitt „Code signing policy“ in der README (gibt es schon), Link darauf in jedem Release (macht der Workflow)

## 2. Antrag stellen

Formular: <https://signpath.org/apply>

Für den Antrag nützlich:
- **Projekt:** ScanMe, <https://github.com/SoufianElMakhfi/scanme>, Lizenz GPL-3.0
- **Beschreibung:** Defensiver Sicherheitsscanner für den eigenen Windows-PC (Blue Team): prüft Prozesse,
  Autostarts, Ereignisprotokolle und Dateien auf Spuren von Malware und erklärt Funde verständlich.
- **Wichtig, weil die Foundation keine „Hacking-Tools“ signiert:** ScanMe untersucht ausschließlich den lokalen
  PC, scannt keine fremden Systeme oder Netzwerke, nutzt keine Schwachstellen aus und umgeht keine
  Schutzmaßnahmen. Jede Änderung (Quarantäne, Deaktivieren …) zeigt ScanMe vorher an, sie muss bestätigt
  werden und lässt sich rückgängig machen.
- **Installation/Deinstallation:** Portables Programm ohne Installation. Daten liegen in `C:\ProgramData\ScanMe`.
- **Netzwerk:** nur Update-Prüfung und signierte Regeln von GitHub, abschaltbar (siehe README → Datenschutz).

## 3. Nach der Freigabe in SignPath einrichten

1. Projekt mit dem Slug **`scanme`** anlegen (oder den Slug im Workflow anpassen).
2. Unter *Trusted Build Systems* das vordefinierte **GitHub.com** hinzufügen und mit dem Projekt verknüpfen.
3. Artefaktkonfiguration **`default`**: Inhalt von [.signpath/artifact-configuration.xml](.signpath/artifact-configuration.xml) einfügen.
4. Signing Policy mit dem Slug **`release-signing`** (Zertifikat der Foundation) anlegen und dich als Approver eintragen.
5. Einen CI-Benutzer mit **Submitter**-Rechten anlegen und ein API-Token erzeugen.

## 4. In GitHub hinterlegen

*Repository → Settings → Secrets and variables → Actions*

| Art | Name | Wert |
|---|---|---|
| Secret | `SIGNPATH_API_TOKEN` | API-Token aus Schritt 3.5 |
| Variable | `SIGNPATH_ORGANIZATION_ID` | Organisations-ID aus SignPath |

## 5. Release erstellen

```powershell
git tag v1.0.4
git push origin v1.0.4
```

Der Workflow lädt die EXEs zu SignPath hoch und wartet bis zu einer Stunde auf deine Freigabe
(E-Mail bzw. SignPath-Weboberfläche). Danach prüft er, ob jede EXE gültig signiert ist, und veröffentlicht
erst dann das Release. Eine fehlende oder ungültige Signatur bricht das Release ab.

Nach dem ersten signierten Release in der README den **Status-Hinweis** unter „Code signing policy“ und den
SmartScreen-Hinweis unter „Download & Start“ anpassen.

## Was die Signatur bringt – und was nicht

- Windows zeigt einen Herausgeber statt „Unbekannter Herausgeber“. Manipulierte Dateien erkennt man sofort,
  weil ihre Signatur ungültig wird.
- Virenscanner stufen signierte Programme seltener fälschlich als verdächtig ein.
- **SmartScreen verschwindet nicht sofort.** Seit 2024 bekommt kein Zertifikat mehr automatisch Vertrauen.
  Das Zertifikat sammelt Reputation über die Downloads. Weil alle Versionen mit demselben Zertifikat signiert
  sind, wächst die Reputation über Releases hinweg; unsignierte Dateien beginnen jedes Mal bei null.
