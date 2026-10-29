# ScanMe – Hinweise für Claude

Unterhaltung und Commit-Nachrichten auf Deutsch.

## Nach jeder Änderung (ohne Nachfrage)

1. **Bauen und testen:** `dotnet build ScanMe.sln` und `dotnet test tests/ScanMe.Tests` müssen grün sein.
2. **Committen:** deutsche Commit-Nachricht im Stil der bisherigen Commits (`git log`).
3. **Pushen** nach `origin` (github.com/SoufianElMakhfi/scanme). Nie direkt auf `main` committen: auf einem
   Feature-Branch arbeiten; ist der aktuelle Branch noch nicht gemergt, darauf weiterarbeiten. Neue Branches mit `-u` pushen.
4. **Veröffentlichen:** `powershell -ExecutionPolicy Bypass -File publish.ps1` ausführen. Das Skript testet erneut, baut
   eigenständige EXEs nach `publish\win-x64\` und lässt Defender darüber laufen. Den Ordner ignoriert git absichtlich,
   die EXEs gehören nicht ins Repository.

## Umgebung

- Das .NET-8-SDK liegt unter `C:\Users\elmakhfis\AppData\Local\Microsoft\dotnet\dotnet.exe`; unter
  `C:\Program Files\dotnet` ist nur die Runtime. Für `publish.ps1` vorher `PATH` und `DOTNET_ROOT` auf diesen Ordner setzen.
- `gh` ist nicht installiert: Pull Requests und Releases legt der Nutzer im Browser an.
- Die CLI verlangt Adminrechte (Manifest). Zum Testen ohne UAC: `dotnet src/ScanMe.Cli/bin/Debug/net8.0-windows10.0.17763.0/win-x64/scanme-cli.dll …`
- `.cs`-, `.xaml`- und Projektdateien haben CRLF-Zeilenenden (`.gitattributes`).
- Defender sperrt frisch geschriebene EXEs kurz; `publish.ps1` versucht es dann von selbst erneut.

## Scan-Grundsatz

Gründlichkeit geht vor Geschwindigkeit. Der Nutzer verwendet überwiegend den vollständigen Scan
(`ScanProfile.Full`), wie lange er dauert, spielt keine Rolle. Dort keine Zeitbudgets, Datei- oder Größenlimits
einbauen; solche Grenzen nur im Schnellscan oder als Schutz gegen Hänger (z. B. Timeout je Datei).
