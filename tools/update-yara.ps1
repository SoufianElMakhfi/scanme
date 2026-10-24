# Holt YARA-X (VirusTotal) und die YARA-Forge-Regeln in den festen Versionen aus tools\yara-sources.json
# und erzeugt daraus deps\yara\ (wird beim Build als Data\yara\ neben die EXE kopiert, nur win-x64).
#   powershell -ExecutionPolicy Bypass -File tools\update-yara.ps1
# Wird automatisch von publish.ps1 und vom GitHub-Workflow aufgerufen; laedt nur neu, wenn sich Versionen aendern.
#
# Die Regeln werden nie als lesbarer Text gespeichert: Sie enthalten Zeichenfolgen aus echter Malware, und
# Defender haelt sie (auch kompiliert oder nur gzip-gepackt) selbst fuer Schadsoftware. Das Regelpaket ist daher
# gzip-gepackt und mit einem festen Schluesselstrom verwuerfelt – kein Geheimnis (der Code ist offen), nur damit die
# Datei nicht wie Malware-Text aussieht. Entpackt wird ausschliesslich im Arbeitsspeicher (RulePack.cs).
param([switch]$Force)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$config = Get-Content (Join-Path $PSScriptRoot "yara-sources.json") -Raw | ConvertFrom-Json
$out = Join-Path $root "deps\yara"
$stamp = Join-Path $out "stamp.txt"
$wanted = "$($config.yaraX.sha256) $($config.yaraForge.sha256) $((Get-FileHash (Join-Path $PSScriptRoot 'yara-sources.json')).Hash) $((Get-FileHash $PSCommandPath).Hash)"

if (-not $Force -and (Test-Path $stamp) -and (Get-Content $stamp -Raw).Trim() -eq $wanted) {
    "YARA: aktuell ($($config.yaraX.version), Regeln $($config.yaraForge.release))"
    return
}
New-Item -ItemType Directory -Force $out | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

function Get-Verified([string]$url, [string]$sha256) {
    $bytes = (New-Object Net.WebClient).DownloadData($url)
    $hash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace("-", "").ToLowerInvariant()
    if ($hash -ne $sha256) { throw "Pruefsumme stimmt nicht: $url`n  erwartet $sha256`n  erhalten $hash" }
    return , $bytes
}

function Open-Zip([byte[]]$bytes) { New-Object IO.Compression.ZipArchive((New-Object IO.MemoryStream(, $bytes)), [IO.Compression.ZipArchiveMode]::Read) }

# --- 1. YARA-X ---
$zip = Open-Zip (Get-Verified $config.yaraX.url $config.yaraX.sha256)
$entry = $zip.GetEntry("yara_x_capi.dll")
$fs = [IO.File]::Create((Join-Path $out "yara_x_capi.dll")); $entry.Open().CopyTo($fs); $fs.Close()
$yaraXLicense = (New-Object Net.WebClient).DownloadString($config.yaraX.licenseUrl)

# --- 2. Regeln: nur lizenzgepruefte Quellen, nur im Speicher ---
$zip = Open-Zip (Get-Verified $config.yaraForge.url $config.yaraForge.sha256)
$reader = New-Object IO.StreamReader($zip.GetEntry($config.yaraForge.entry).Open(), [Text.Encoding]::UTF8)
$text = $reader.ReadToEnd().Replace("`r`n", "`n")
$reader.Close()

$allowed = @{}
$display = @{}
$config.sources.PSObject.Properties | ForEach-Object { $allowed[$_.Name.ToLowerInvariant()] = $_.Value; $display[$_.Name.ToLowerInvariant()] = $_.Name }

$chunks = [regex]::Split($text, '\n(?=(?:private\s+|global\s+)*rule\s+\w+)')
$imports = [regex]::Matches($chunks[0], '(?m)^import\s+"\w+"') | ForEach-Object { $_.Value }
$kept = New-Object Text.StringBuilder
$info = New-Object Text.StringBuilder
$perSource = @{}
$skipped = 0

function Get-Meta([string]$rule, [string]$name) {
    $m = [regex]::Match($rule, $name + '\s*=\s*"((?:[^"\\]|\\.)*)"')
    if ($m.Success) { ($m.Groups[1].Value -replace '\\"', '"' -replace '[\t\r\n]', ' ').Trim() } else { "" }
}

foreach ($chunk in $chunks | Select-Object -Skip 1) {
    $name = [regex]::Match($chunk, '^(?:private\s+|global\s+)*rule\s+(\w+)').Groups[1].Value
    $repo = [regex]::Match($chunk, 'source_url\s*=\s*"https://github\.com/([^/"]+/[^/"]+)').Groups[1].Value.ToLowerInvariant()
    if (-not $allowed.ContainsKey($repo)) { $skipped++; continue }
    [void]$kept.Append($chunk).Append("`n")
    $score = [regex]::Match($chunk, '\bscore\s*=\s*(\d+)').Groups[1].Value
    [void]$info.Append($name).Append("`t").Append($score).Append("`t").Append($display[$repo]).Append("`t").
        Append((Get-Meta $chunk "author")).Append("`t").Append((Get-Meta $chunk "description")).Append("`n")
    $perSource[$repo] = 1 + $(if ($perSource.ContainsKey($repo)) { $perSource[$repo] } else { 0 })
}
$ruleCount = ($perSource.Values | Measure-Object -Sum).Sum

# Paket: Kopfzeilen, Regelinfos (Name, Score, Quelle, Autor, Beschreibung), Trenner, Regeltext
$payload = "SCANME-YARA-PACK 1`nforge=$($config.yaraForge.release)`nyarax=$($config.yaraX.version)`nrules=$ruleCount`n" +
           $info.ToString() + "---`n" + ($imports -join "`n") + "`n" + $kept.ToString()

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
public static class ScanMeRulePackWriter {
    // Muss zu ScanMe.Core.Yara.RulePack passen (Format, Schluessel, Zaehler).
    public static byte[] Encode(string payload) {
        var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, true)) {
            byte[] raw = Encoding.UTF8.GetBytes(payload);
            gz.Write(raw, 0, raw.Length);
        }
        byte[] data = ms.ToArray();
        byte[] key = Encoding.ASCII.GetBytes("ScanMe rule pack v1");
        using (var sha = SHA256.Create()) {
            byte[] block = new byte[key.Length + 8];
            Buffer.BlockCopy(key, 0, block, 0, key.Length);
            for (long i = 0; i * 32 < data.Length; i++) {
                Buffer.BlockCopy(BitConverter.GetBytes(i), 0, block, key.Length, 8);
                byte[] ks = sha.ComputeHash(block);
                for (int j = 0; j < 32 && i * 32 + j < data.Length; j++) data[i * 32 + j] ^= ks[j];
            }
        }
        byte[] magic = Encoding.ASCII.GetBytes("SMYR1");
        byte[] result = new byte[magic.Length + data.Length];
        Buffer.BlockCopy(magic, 0, result, 0, magic.Length);
        Buffer.BlockCopy(data, 0, result, magic.Length, data.Length);
        return result;
    }
}
"@
[IO.File]::WriteAllBytes((Join-Path $out "rules.bin"), [ScanMeRulePackWriter]::Encode($payload))
$payload = $null; $text = $null; $kept = $null

# --- 3. Lizenzhinweise ---
$notice = New-Object Text.StringBuilder
[void]$notice.AppendLine("ScanMe - YARA-Regeln und YARA-X")
[void]$notice.AppendLine("================================")
[void]$notice.AppendLine("")
[void]$notice.AppendLine("Regeln: YARA Forge, Paket 'core', Release $($config.yaraForge.release) (https://github.com/YARAHQ/yara-forge),")
[void]$notice.AppendLine("gefiltert auf Quellen mit geprueften Lizenzen. Jede Regel behaelt ihre Metadaten (author, reference,")
[void]$notice.AppendLine("source_url, license_url); ScanMe zeigt Regelname, Autor und Quelle bei jedem Treffer an.")
[void]$notice.AppendLine("Detection Rule License 1.1: https://github.com/SigmaHQ/Detection-Rule-License")
[void]$notice.AppendLine("CC BY-SA 4.0 (Malpedia): https://creativecommons.org/licenses/by-sa/4.0/ - die Regeln aus dieser Quelle")
[void]$notice.AppendLine("werden unter derselben Lizenz weitergegeben.")
[void]$notice.AppendLine("")
[void]$notice.AppendLine("Quellen (Regeln, Lizenz):")
foreach ($k in ($perSource.Keys | Sort-Object)) {
    [void]$notice.AppendLine(("  https://github.com/{0}  -  {1} Regeln, {2}" -f $display[$k], $perSource[$k], $allowed[$k]))
}
[void]$notice.AppendLine("")
[void]$notice.AppendLine("YARA-X $($config.yaraX.version) (yara_x_capi.dll), VirusTotal, https://github.com/VirusTotal/yara-x - $($config.yaraX.license):")
[void]$notice.AppendLine("")
[void]$notice.Append($yaraXLicense)
[IO.File]::WriteAllText((Join-Path $out "NOTICE.txt"), $notice.ToString(), (New-Object Text.UTF8Encoding $false))

[IO.File]::WriteAllText($stamp, $wanted)
"YARA: YARA-X {0}, {1} Regeln aus {2} Quellen ({3} ohne gepruefte Lizenz ausgelassen), Paket {4:N0} KB -> {5}" -f `
    $config.yaraX.version, $ruleCount, $perSource.Count, $skipped, ((Get-Item (Join-Path $out "rules.bin")).Length / 1KB), $out
