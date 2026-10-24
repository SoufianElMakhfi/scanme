# Mitwirken an ScanMe

Danke, dass du ScanMe verbessern möchtest! Beiträge sind willkommen – Fehlalarm-Meldungen,
neue Erkennungsregeln, Fehlerbehebungen und Übersetzungen.

## Fehlalarm oder übersehene Malware melden

Am meisten hilft ScanMe ein guter Fehlalarm-Bericht: **Issues → „Fehlalarm melden“**.
Bitte angeben: Titel des Fundes, Score, Indikatoren (Button „Details kopieren“) und um welches
Programm es sich tatsächlich handelt. **Keine Passwörter, Benutzernamen oder privaten Pfade posten** –
ersetze sie z. B. durch `<USER>`.

Für übersehene Malware: SHA256-Hash und Name aus VirusTotal reichen. **Lade niemals Malware-Dateien
ins Repository oder in Issues hoch.**

## Entwicklung

```powershell
dotnet build ScanMe.sln
dotnet test tests/ScanMe.Tests      # muss vor jedem Pull Request grün sein
```

Leitlinien:
- **Sicherheit zuerst:** Änderungen an `SafetyGuard`, Quarantäne oder Aktionen brauchen Tests.
  Windows-Komponenten dürfen niemals gelöscht oder beendet werden.
- **Fehlalarme vermeiden:** Neue Indikatoren an einem normalen System gegenprüfen
  (`scanme-cli.exe --all`). Ein generischer API-Name allein ist kein Malware-Beweis.
- **Texte für Nutzer** auf Deutsch, verständlich für Laien: *was* gefunden wurde, *warum* es wichtig ist,
  *was* zu tun ist.
- Code-Stil wie im bestehenden Code, ein Pull Request pro Thema.

## Neue Erkennungsregeln

Es gibt zwei Wege:

1. **Eingebaute Regeln** in `src/ScanMe.Core/Knowledge/` – werden mit der nächsten Version ausgeliefert.
2. **Online-Regeln** in `rules/rules.json` – erreichen alle Nutzer sofort, ohne neue Version.
   Online-Regeln können Erkennungen nur *ergänzen*. Sie werden vom Maintainer geprüft und
   **signiert**; Pull Requests dürfen `rules.json` ändern, die Signatur (`rules.json.sig`)
   erzeugt ausschließlich der Maintainer.

Bitte zu jeder Regel eine Quelle angeben (Analysebericht, MITRE-ATT&CK-ID, CVE).

## Für Maintainer: Regeln veröffentlichen

```powershell
scanme-cli.exe --rules-sign rules/rules.json     # nutzt %USERPROFILE%\.scanme\rules-signing-key.pem
dotnet test tests/ScanMe.Tests                   # prüft u. a. die Signatur
git add rules/ ; git commit ; git push
```
`version` in `rules.json` bei jeder Änderung erhöhen. Der private Schlüssel gehört **nie** ins Repository
und muss sicher gesichert werden – geht er verloren, braucht es einen neuen Schlüssel und eine neue
ScanMe-Version.

## Lizenz

Mit deinem Beitrag stimmst du zu, dass er unter der [GPL-3.0](LICENSE) veröffentlicht wird.
