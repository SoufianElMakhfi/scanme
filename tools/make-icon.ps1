# Erzeugt src/ScanMe.App/Assets/scanme.ico (Schild mit Haken) in mehreren Groessen.
# Aufruf: powershell -ExecutionPolicy Bypass -File tools/make-icon.ps1
param([string]$Out = "$PSScriptRoot\..\src\ScanMe.App\Assets\scanme.ico")

Add-Type -AssemblyName System.Drawing
$sizes = 16, 24, 32, 48, 64, 128, 256
$pngs = @()

foreach ($s in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap $s, $s
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)
    $k = $s / 24.0

    # Schild (Pfad wie im UI-Logo, 24x24-Raster)
    $shield = New-Object System.Drawing.Drawing2D.GraphicsPath
    $shield.AddLine(12*$k, 1*$k, 3*$k, 5*$k)
    $shield.AddLine(3*$k, 5*$k, 3*$k, 11*$k)
    $shield.AddBezier(3*$k, 11*$k, 3*$k, 16.55*$k, 6.84*$k, 21.74*$k, 12*$k, 23*$k)
    $shield.AddBezier(12*$k, 23*$k, 17.16*$k, 21.74*$k, 21*$k, 16.55*$k, 21*$k, 11*$k)
    $shield.AddLine(21*$k, 11*$k, 21*$k, 5*$k)
    $shield.CloseFigure()
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush (New-Object System.Drawing.PointF 0, 0), (New-Object System.Drawing.PointF 0, $s), `
        ([System.Drawing.Color]::FromArgb(255, 106, 162, 255)), ([System.Drawing.Color]::FromArgb(255, 47, 104, 230))
    $g.FillPath($brush, $shield)

    # Haken
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), ([Math]::Max(1.5, 2.2 * $k))
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
    $g.DrawLines($pen, [System.Drawing.PointF[]]@((New-Object System.Drawing.PointF (7.5*$k), (12.5*$k)), (New-Object System.Drawing.PointF (10.5*$k), (15.5*$k)), (New-Object System.Drawing.PointF (16.5*$k), (9*$k))))

    $g.Dispose()
    if ($s -ge 256) {
        # 256 px als PNG (wird von Windows so erwartet)
        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $pngs += ,@($s, $ms.ToArray())
    } else {
        # Kleine Groessen als 32-Bit-DIB (BITMAPINFOHEADER + BGRA bottom-up + AND-Maske) – kompatibel mit GDI+/NotifyIcon
        $ms = New-Object System.IO.MemoryStream
        $w = New-Object System.IO.BinaryWriter $ms
        $w.Write([UInt32]40); $w.Write([Int32]$s); $w.Write([Int32]($s * 2)); $w.Write([UInt16]1); $w.Write([UInt16]32)
        $w.Write([UInt32]0); $w.Write([UInt32]0); $w.Write([Int32]0); $w.Write([Int32]0); $w.Write([UInt32]0); $w.Write([UInt32]0)
        for ($y = $s - 1; $y -ge 0; $y--) {
            for ($x = 0; $x -lt $s; $x++) {
                $c = $bmp.GetPixel($x, $y)
                $w.Write([byte]$c.B); $w.Write([byte]$c.G); $w.Write([byte]$c.R); $w.Write([byte]$c.A)
            }
        }
        $maskRow = [int]([Math]::Ceiling($s / 32.0) * 4)
        $w.Write((New-Object byte[] ($maskRow * $s)))
        $w.Flush()
        $pngs += ,@($s, $ms.ToArray())
    }
    $bmp.Dispose()
}

# ICO-Container mit PNG-Eintraegen schreiben
New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
$fs = [System.IO.File]::Create($Out)
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$pngs.Count)
$offset = 6 + 16 * $pngs.Count
foreach ($p in $pngs) {
    $s = $p[0]; $data = $p[1]
    $dim = if ($s -ge 256) { 0 } else { $s }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([UInt16]1); $bw.Write([UInt16]32); $bw.Write([UInt32]$data.Length); $bw.Write([UInt32]$offset)
    $offset += $data.Length
}
foreach ($p in $pngs) { $bw.Write($p[1]) }
$bw.Close()
"Icon geschrieben: $Out"
