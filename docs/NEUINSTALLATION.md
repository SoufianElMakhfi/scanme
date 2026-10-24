# Windows sauber neu aufsetzen – nach einem Befall

Diese Anleitung ist für den Fall gedacht, dass ScanMe oder Defender echte Schadsoftware gefunden hat
(z. B. Krypto-Miner, Passwortdiebe/„Stealer“, Fernzugriff). Ein befallenes Windows lässt sich nie
sicher „sauber putzen“ – ein Neuaufsetzen ist der einzige Weg, sicher zu sein.

Reihenfolge ist wichtig: **erst Konten sichern, dann Daten sichern, dann neu installieren.**

---

## 1. Konten sichern – von einem ANDEREN Gerät (Handy, fremder PC)

Ein Passwortdieb hat in der Regel gespeicherte Browser-Passwörter, Cookies (angemeldete Sitzungen)
und Token kopiert. Auf dem befallenen PC eingegebene neue Passwörter könnten mitgelesen werden.

1. **E-Mail-Konto zuerst** (darüber lässt sich alles andere zurücksetzen): neues Passwort,
   Zwei-Faktor-Anmeldung per App oder Passkey, „Von allen Geräten abmelden“.
2. Passwort-Manager, Banking, PayPal, Amazon.
3. Google/Microsoft/Apple-Konto: unbekannte Geräte entfernen, „Überall abmelden“.
4. Discord, Steam, Epic, Social Media, Notion usw.: Passwort ändern **und** alle Sitzungen abmelden
   – gestohlene Cookies funktionieren sonst weiter, auch nach der Passwortänderung.
5. Unter https://haveibeenpwned.com prüfen, welche Adressen betroffen sind.

### Zusätzlich für Entwickler

- **GitHub:** Settings → Sessions (abmelden), Personal Access Tokens, SSH-Keys, GPG-Keys,
  OAuth-/GitHub-Apps, Deploy-Keys prüfen und neu erstellen. Security-Log ansehen.
- **API-Schlüssel rotieren:** Alles, was in `.env`-Dateien, Shell-Profilen oder Konfigurationen stand
  (KI-Anbieter, Cloud, Datenbanken, Supabase/Firebase, Stripe, npm/PyPI-Token, Docker-Registry).
  Alte Schlüssel beim Anbieter **löschen**, nicht nur neue anlegen.
- **Signier-Schlüssel** (Code-Signing, Release-Schlüssel, z. B. der ScanMe-Regelschlüssel):
  nach der Neuinstallation neu erzeugen und den alten zurückziehen.
- Abrechnungen bei Cloud-/KI-Anbietern auf ungewöhnliche Nutzung prüfen.

## 2. Daten sichern – nur Dateien, keine Programme

Auf einen externen Datenträger kopieren:

- Dokumente, Bilder, Videos, Musik, Spielstände.
- Quellcode: am besten alles nach GitHub pushen, dann nach der Neuinstallation frisch klonen.
- **Nicht** sichern: `.exe`, `.msi`, `.bat`, `.ps1`, `.dll`, `.scr`, `.lnk`, Installationsdateien,
  Cracks/Cheats/Mods, ganze `AppData`-Ordner, Browser-Profile.
- `.env`-Dateien und Schlüssel **nicht** mitnehmen – die werden ohnehin neu erstellt (siehe oben).

Notieren: welche Programme Sie wieder brauchen (Liste, nicht die Installer).

## 3. Neu installieren

1. Installationsmedium erstellen – am besten an einem anderen, sauberen PC:
   https://www.microsoft.com/software-download/windows11 („Media Creation Tool“, USB-Stick ≥ 8 GB).
2. Vom USB-Stick starten (Boot-Menü, meist F8/F11/F12/Entf).
3. **Benutzerdefinierte Installation** wählen und auf dem Systemlaufwerk **alle Partitionen löschen**.
   Nicht „Eigene Dateien behalten“ und nicht „Diesen PC zurücksetzen“ verwenden.
4. Während der Installation am besten ohne Internet; die Windows-Lizenz aktiviert sich danach automatisch.
5. Im UEFI/BIOS: Secure Boot und TPM einschalten, Firmware vom Hersteller aktualisieren.

## 4. Nach der Installation

1. **Windows Update** bis nichts mehr kommt (inkl. optionaler Treiber-Updates), neu starten.
2. **Zwei Konten:** ein Administrator-Konto nur für Installationen und ein **Standardkonto** für den Alltag.
   Viele Schadprogramme scheitern ohne Adminrechte.
3. Programme nur von der offiziellen Herstellerseite, aus dem Microsoft Store oder per `winget` installieren.
   **Keine Cracks, Cheats, „Loader“ oder Key-Generatoren** – sie sind der häufigste Weg für Passwortdiebe.
   Keine Defender-Ausnahmen anlegen, nur weil ein Programm es verlangt.
4. **ScanMe** (aus den GitHub-Releases) als Administrator starten:
   - *Schutz-Assistent* → „Empfohlene Einstellungen anwenden“ (Angriffsregeln zuerst im Testmodus).
   - Für Skript- und KI-Tool-Nutzer: *Profi-Aufzeichnung mit Microsoft Sysmon* einschalten.
   - Vollständigen Scan ausführen.
   - *Übersicht* → „Zustand als sauber merken“ und „Auf USB sichern“. Ab jetzt meldet ScanMe jede Veränderung.
5. Browser: Erweiterungen nur einzeln und bewusst neu installieren, nicht das alte Profil importieren.
6. Gesicherte Daten erst mit Microsoft Defender scannen (Rechtsklick → „Mit Microsoft Defender überprüfen“),
   dann zurückkopieren.
7. Nach einigen Tagen: ScanMe-Scan wiederholen und die Änderungen gegenüber dem sauberen Zustand ansehen.
