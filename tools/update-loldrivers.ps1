# Aktualisiert die eingebaute Liste verwundbarer und boesartiger Treiber aus LOLDrivers (https://www.loldrivers.io, Apache-2.0).
#   powershell -ExecutionPolicy Bypass -File tools\update-loldrivers.ps1
# Vor jedem Release ausfuehren und das Ergebnis (src\ScanMe.Core\Knowledge\Data\loldrivers.json) committen.
# Uebernommen werden nur die Fingerabdruecke (SHA256 und Authentihash), Dateinamen, Kategorie und CVE-Nummern.
param([string]$Source = "https://www.loldrivers.io/api/drivers.json")

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$target = Join-Path $root "src\ScanMe.Core\Knowledge\Data\loldrivers.json"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$raw = (New-Object Net.WebClient).DownloadString($Source)

# Windows PowerShell 5.1: ConvertFrom-Json scheitert an grossen Dateien (MaxJsonLength) – dort den Serializer direkt nutzen.
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $drivers = $raw | ConvertFrom-Json
    function Get-Field($obj, $name) { $obj.$name }
} else {
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = [int]::MaxValue
    $drivers = $serializer.DeserializeObject($raw)
    function Get-Field($obj, $name) { if ($obj -is [System.Collections.IDictionary] -and $obj.ContainsKey($name)) { $obj[$name] } else { $null } }
}

function Get-Hashes($samples, $field) {
    @($samples | ForEach-Object {
        $v = if ($field -eq "Authentihash") { Get-Field (Get-Field $_ "Authentihash") "SHA256" } else { Get-Field $_ $field }
        if ($v -match '^[0-9a-fA-F]{64}$') { $v.ToLowerInvariant() }
    } | Sort-Object -Unique)
}

$out = foreach ($d in $drivers) {
    $samples = @(Get-Field $d "KnownVulnerableSamples")
    # @(...) noetig: PowerShell macht aus Rueckgaben mit einem Element sonst einen Einzelwert
    $sha = @(Get-Hashes $samples "SHA256")
    $auth = @(Get-Hashes $samples "Authentihash")
    if ($sha.Count + $auth.Count -eq 0) { continue }

    $names = @(@(Get-Field $d "Tags") + @($samples | ForEach-Object { Get-Field $_ "Filename" }) |
        Where-Object { $_ -match '\.sys$' } | Sort-Object -Unique)
    $text = (@(Get-Field $d "Resources") + @(Get-Field $d "Tags") + @(Get-Field (Get-Field $d "Commands") "Description")) -join " "
    $cves = @([regex]::Matches($text, 'CVE-\d{4}-\d{4,}') | ForEach-Object { $_.Value.ToUpperInvariant() } | Sort-Object -Unique)

    [ordered]@{
        id           = Get-Field $d "Id"
        category     = if ((Get-Field $d "Category") -eq "malicious") { "malicious" } else { "vulnerable" }
        names        = $names
        cves         = $cves
        sha256       = $sha
        authentihash = $auth
    }
}

$result = [ordered]@{
    source    = "https://www.loldrivers.io"
    license   = "Apache-2.0"
    generated = (Get-Date).ToString("yyyy-MM-dd")
    drivers   = @($out)
}
New-Item -ItemType Directory -Force (Split-Path $target) | Out-Null
$json = $result | ConvertTo-Json -Depth 5 -Compress
[IO.File]::WriteAllText($target, $json, (New-Object Text.UTF8Encoding $false))

$m = @($out | Where-Object { $_.category -eq "malicious" }).Count
"{0} Treiber ({1} verwundbar, {2} boesartig), {3:N0} KB -> {4}" -f $out.Count, ($out.Count - $m), $m, ((Get-Item $target).Length / 1KB), $target
