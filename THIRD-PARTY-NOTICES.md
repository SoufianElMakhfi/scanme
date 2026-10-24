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
