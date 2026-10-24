# Erstellt eigenstaendige Single-File-EXEs (keine .NET-Installation auf dem Ziel-PC noetig).
#   powershell -ExecutionPolicy Bypass -File publish.ps1            -> x64
#   powershell -ExecutionPolicy Bypass -File publish.ps1 -Arm64     -> zusaetzlich ARM64 (Surface/Snapdragon)
param([switch]$Arm64, [string]$Configuration = "Release")

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$rids = @("win-x64")
if ($Arm64) { $rids += "win-arm64" }

dotnet test "$root\tests\ScanMe.Tests" -c $Configuration
if ($LASTEXITCODE -ne 0) { throw "Tests fehlgeschlagen - Veroeffentlichung abgebrochen." }

foreach ($rid in $rids) {
    $out = Join-Path $root "publish\$rid"
    if (Test-Path $out) { Remove-Item $out -Recurse -Force }
    foreach ($proj in @("src\ScanMe.App\ScanMe.App.csproj", "src\ScanMe.Cli\ScanMe.Cli.csproj")) {
        # Virenscanner sperren frisch geschriebene EXEs kurz zum Pruefen - bei Sperrfehlern erneut versuchen.
        $ok = $false
        for ($attempt = 1; $attempt -le 3 -and -not $ok; $attempt++) {
            dotnet publish (Join-Path $root $proj) -c $Configuration -r $rid -o $out `
                --self-contained true `
                -p:PublishSingleFile=true `
                -p:IncludeNativeLibrariesForSelfExtract=true `
                -p:EnableCompressionInSingleFile=true `
                -p:DebugType=none
            $ok = ($LASTEXITCODE -eq 0)
            if (-not $ok) { Write-Warning "Publish-Versuch $attempt fehlgeschlagen ($proj) - neuer Versuch in 5 s"; Start-Sleep -Seconds 5 }
        }
        if (-not $ok) { throw "Publish fehlgeschlagen: $proj ($rid)" }
    }
    # Unvollstaendig geschriebene Bundles erkennen (eigenstaendige EXEs sind deutlich groesser als 20 MB)
    Get-ChildItem $out -Filter *.exe | Where-Object { $_.Length -lt 20MB } | ForEach-Object { throw "Unvollstaendige Datei: $($_.Name) ($([math]::Round($_.Length / 1MB, 1)) MB)" }
    Get-ChildItem $out -Filter *.exe | ForEach-Object {
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        "{0,-18} {1,8:N1} MB  SHA256 {2}" -f $_.Name, ($_.Length / 1MB), $hash
    }
}
"Fertig: $root\publish"
