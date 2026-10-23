# ScanMe – Blue Team PC Scanner für Windows 10/11

ScanMe durchleuchtet einen Windows-PC vollständig aus Sicht eines Blue Teams:
versteckte und verdächtige Prozesse, Persistenz-Mechanismen (Autostarts, Dienste,
geplante Tasks, WMI), Netzwerkverbindungen, Spuren alter Angriffe oder Phishing,
Malware, unsichere Sicherheitseinstellungen und Kompatibilitätsprobleme – mit
Erklärung und Empfehlung zu jedem Fund.

**Grundsatz:** Windows-eigene Komponenten (Microsoft-signiert, Systempfade,
kritische Prozesse) werden niemals gelöscht oder beendet. Jede Aktion
(Quarantäne, Autostart deaktivieren) ist rückgängig machbar.

## Techstack

| Teil | Technologie | Warum |
|---|---|---|
| Engine | C# / .NET 8 (`ScanMe.Core`) | Direkter Zugriff auf Win32/NT-API, WMI, Registry, Event-Logs, Authenticode |
| Oberfläche | WPF (`ScanMe.App`) | Native Windows-Desktop-App |
| Konsole | `ScanMe.Cli` | Scans ohne GUI, JSON-Export, Tests |
| Auslieferung | Self-contained Single-File EXE | Läuft auf jedem Windows 10/11 x64 ohne .NET-Installation |

## Bauen

Voraussetzung: [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

```powershell
dotnet build ScanMe.sln
```

Die App fordert beim Start Administratorrechte an, da ein vollständiger Scan
(fremde Prozesse, Security-Eventlog, Dienste, geplante Tasks) diese benötigt.
