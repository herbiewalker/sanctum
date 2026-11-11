# Renders deploy/icon.png (512x512): a vault door on a dark rounded tile.
# Run:  powershell -NoProfile -File deploy/icon/make-icon.ps1
# The PNG is generated, so edit this script and re-run rather than editing the PNG.
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

$S = 512
$out = Join-Path (Split-Path -Parent $PSScriptRoot) 'icon.png'
$bmp = New-Object System.Drawing.Bitmap $S, $S, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'AntiAlias'
$g.PixelOffsetMode = 'HighQuality'
$g.InterpolationMode = 'HighQualityBicubic'
$g.Clear([System.Drawing.Color]::Transparent)

function C($hex, $a = 255) { $c = [System.Drawing.ColorTranslator]::FromHtml($hex); [System.Drawing.Color]::FromArgb($a, $c.R, $c.G, $c.B) }
function RoundRect($x, $y, $w, $h, $r) {
  $p = New-Object System.Drawing.Drawing2D.GraphicsPath
  $d = $r * 2
  $p.AddArc($x, $y, $d, $d, 180, 90); $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
  $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90); $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
  $p.CloseFigure(); $p
}
function Circle($cx, $cy, $r) { New-Object System.Drawing.RectangleF ($cx - $r), ($cy - $r), (2 * $r), (2 * $r) }
function LGB($rect, $c1, $c2, $angle) { New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect, $c1, $c2, $angle }

# --- tile -------------------------------------------------------------------
$tile = RoundRect 8 8 ($S - 16) ($S - 16) 108
$g.FillPath((LGB (New-Object System.Drawing.RectangleF 0, 0, $S, $S) (C '#18284a') (C '#080e1c') 90), $tile)
$g.DrawPath((New-Object System.Drawing.Pen (C '#22d3ee' 90), 4), $tile)

$cx = 256; $cy = 256

# --- soft glow behind the door ---------------------------------------------
$glow = New-Object System.Drawing.Drawing2D.GraphicsPath
$glow.AddEllipse((Circle $cx $cy 215))
$pg = New-Object System.Drawing.Drawing2D.PathGradientBrush $glow
$pg.CenterColor = C '#22d3ee' 70
$pg.SurroundColors = @((C '#22d3ee' 0))
$g.FillPath($pg, $glow)

# --- door -------------------------------------------------------------------
$door = Circle $cx $cy 178
$g.FillEllipse((LGB $door (C '#2b4a7a') (C '#12213b') 55), $door)
$g.DrawEllipse((New-Object System.Drawing.Pen (C '#22d3ee'), 14), $door)
$g.DrawEllipse((New-Object System.Drawing.Pen (C '#7dd3fc' 120), 3), (Circle $cx $cy 146))

# bolts
$bolt = New-Object System.Drawing.SolidBrush (C '#a5f3fc')
for ($i = 0; $i -lt 12; $i++) {
  $a = [Math]::PI * 2 * $i / 12
  $g.FillEllipse($bolt, (Circle ($cx + 160 * [Math]::Cos($a)) ($cy + 160 * [Math]::Sin($a)) 6))
}

# --- handle wheel -----------------------------------------------------------
$spoke = New-Object System.Drawing.Pen (C '#e2e8f0'), 20
$spoke.StartCap = 'Round'; $spoke.EndCap = 'Round'
$shadow = New-Object System.Drawing.Pen (C '#000000' 80), 20
$shadow.StartCap = 'Round'; $shadow.EndCap = 'Round'
$knob = New-Object System.Drawing.SolidBrush (C '#f1f5f9')
for ($i = 0; $i -lt 6; $i++) {
  $a = [Math]::PI * 2 * $i / 6 - [Math]::PI / 2
  $x = $cx + 108 * [Math]::Cos($a); $y = $cy + 108 * [Math]::Sin($a)
  $g.DrawLine($shadow, $cx + 4, $cy + 6, $x + 4, $y + 6)
  $g.DrawLine($spoke, $cx, $cy, $x, $y)
  $g.FillEllipse($knob, (Circle $x $y 17))
}

# --- hub with keyhole -------------------------------------------------------
$hub = Circle $cx $cy 50
$g.FillEllipse((LGB $hub (C '#fde68a') (C '#d97706') 60), $hub)
$g.DrawEllipse((New-Object System.Drawing.Pen (C '#92400e' 160), 3), $hub)
$dark = New-Object System.Drawing.SolidBrush (C '#0b1220')
$g.FillEllipse($dark, (Circle $cx ($cy - 8) 13))
$key = New-Object System.Drawing.Drawing2D.GraphicsPath
$key.AddPolygon(@((New-Object System.Drawing.PointF ($cx - 8), ($cy - 2)), (New-Object System.Drawing.PointF ($cx + 8), ($cy - 2)),
                  (New-Object System.Drawing.PointF ($cx + 14), ($cy + 28)), (New-Object System.Drawing.PointF ($cx - 14), ($cy + 28))))
$g.FillPath($dark, $key)

# --- green status light (the brand's signal node) ---------------------------
$lx = $cx + 130; $ly = $cy + 130
$g.FillEllipse((New-Object System.Drawing.SolidBrush (C '#052e16')), (Circle $lx $ly 24))
$g.FillEllipse((LGB (Circle $lx $ly 17) (C '#86efac') (C '#16a34a') 60), (Circle $lx $ly 17))

$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Host "wrote $out"
