# Prueft Build-Ergebnisse mit Microsoft Defender, ohne etwas zu entfernen, und bricht bei einem Fund ab.
#   powershell -ExecutionPolicy Bypass -File tools\defender-scan.ps1 -Path publish\win-x64
# Wird automatisch von publish.ps1 und vom GitHub-Workflow aufgerufen.
# Hintergrund: Defender hielt eine in die DLL eingebettete Treiber-Hashliste fuer ein Exploit-Werkzeug
# (siehe ScanMe.Core.csproj). Ein solcher Fehlalarm in einem Release wuerde ScanMe bei allen Nutzern blockieren.
param(
    [Parameter(Mandatory = $true)][string[]]$Path,
    [switch]$UpdateSignatures
)

$ErrorActionPreference = "Stop"
$mp = Join-Path $env:ProgramFiles "Windows Defender\MpCmdRun.exe"
if (-not (Test-Path $mp)) { throw "Microsoft Defender (MpCmdRun.exe) nicht gefunden - Pruefung nicht moeglich." }

if ($UpdateSignatures) {
    & $mp -SignatureUpdate | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "Defender-Signaturen konnten nicht aktualisiert werden (Exit $LASTEXITCODE) - pruefe mit vorhandenem Stand." }
}

foreach ($p in $Path) {
    $full = (Resolve-Path $p).Path
    # Exit-Code von MpCmdRun: 0 = keine Funde, 2 = Fund, sonst Fehler. -DisableRemediation: nichts loeschen/verschieben.
    $out = & $mp -Scan -ScanType 3 -File $full -DisableRemediation
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        "Defender: keine Funde in $full"
        continue
    }
    $out | ForEach-Object { Write-Host $_ }
    if ($code -eq 2) {
        throw "Defender meldet einen Fund in $full - abgebrochen. Details: Get-MpThreatDetection / Windows-Sicherheit -> Schutzverlauf."
    }
    throw "Defender-Pruefung fehlgeschlagen (Exit $code) fuer $full."
}
