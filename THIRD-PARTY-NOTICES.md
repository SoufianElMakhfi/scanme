# Drittanbieter-Daten

## LOLDrivers

ScanMe gleicht Treiber mit der Liste bekannt verwundbarer und bösartiger Treiber des Projekts
**LOLDrivers – Living Off The Land Drivers** ab (<https://www.loldrivers.io>,
<https://github.com/magicsword-io/LOLDrivers>).

- Lizenz: Apache License 2.0 – vollständiger Text in
  [src/ScanMe.Core/Knowledge/Data/LICENSE-loldrivers.txt](src/ScanMe.Core/Knowledge/Data/LICENSE-loldrivers.txt)
  (wird als `Data\LICENSE-loldrivers.txt` mit ScanMe ausgeliefert).
- Änderungen: ScanMe übernimmt nur Fingerabdrücke (SHA256, Authentihash), Dateinamen, Kategorie und CVE-Nummern
  und speichert sie in einem eigenen, kompakten Format (`Data\loldrivers.json`, erzeugt mit
  [tools/update-loldrivers.ps1](tools/update-loldrivers.ps1)). Beschreibungen, Erkennungsregeln und
  Befehle aus LOLDrivers sind nicht enthalten.

## YARA-X und YARA-Regeln (nur x64-Version)

- **YARA-X** (VirusTotal, <https://github.com/VirusTotal/yara-x>), BSD-3-Clause – ausgeliefert als
  `Data\yara\yara_x_capi.dll` aus dem offiziellen Release (Version und Prüfsumme in
  [tools/yara-sources.json](tools/yara-sources.json)).
- **YARA-Regeln** aus [YARA Forge](https://github.com/YARAHQ/yara-forge), Paket „core“, gefiltert auf
  18 Quellen mit geprüften Lizenzen (Apache-2.0, BSD-2-Clause, MIT, GPL-3.0, Unlicense,
  Detection Rule License 1.1, CC BY-SA 4.0). Quellen ohne Lizenz werden nicht übernommen.
  Jede Regel behält ihre Metadaten (Autor, Quelle, Lizenz); ScanMe zeigt Regel, Autor und Quelle bei jedem Treffer.
  Die vollständige Liste mit Lizenzen steht in `Data\yara\NOTICE.txt` (erzeugt von
  [tools/update-yara.ps1](tools/update-yara.ps1)).
- Die Regeln aus Malpedia (CC BY-SA 4.0) werden unter derselben Lizenz weitergegeben.
- Das Regelpaket `Data\yara\rules.bin` ist gzip-gepackt und mit einem festen Schlüsselstrom verwürfelt. Das ist
  kein Schutz vor dem Lesen – Format und Schlüssel stehen offen im Quellcode
  ([RulePack.cs](src/ScanMe.Core/Yara/RulePack.cs)) –, sondern verhindert, dass Virenscanner die Regeldatei
  selbst für Malware halten: Sie enthält zwangsläufig Zeichenfolgen aus echter Schadsoftware.
