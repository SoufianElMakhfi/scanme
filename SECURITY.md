# Sicherheitsrichtlinie

ScanMe läuft mit Administratorrechten. Sicherheitslücken in ScanMe selbst nehmen wir daher sehr ernst.

## Sicherheitslücke melden

**Bitte keine öffentlichen Issues für Sicherheitslücken.** Nutze stattdessen
**GitHub → Security → „Report a vulnerability“** (private Meldung). Wir bestätigen den Eingang
innerhalb weniger Tage und veröffentlichen nach der Behebung einen Hinweis.

Relevant sind insbesondere:
- Umgehung des `SafetyGuard` (z. B. Löschen/Beenden von Windows-Komponenten)
- Ausführen von Code durch präparierte Dateien, Registry-Einträge oder Regeldateien
- Umgehung der Signaturprüfung für Online-Regeln
- Rechteausweitung über ScanMe

## Kein Ersatz für Virenschutz

ScanMe ergänzt einen Virenscanner, ersetzt ihn aber nicht. Wenn ScanMe Malware *übersieht*, ist das
kein Sicherheitsproblem von ScanMe – bitte als normales Issue („Fehlalarm / übersehene Malware“) melden.

## Unterstützte Versionen

Sicherheitsupdates gibt es jeweils für die neueste veröffentlichte Version.
