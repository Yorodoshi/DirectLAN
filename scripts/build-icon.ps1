param([switch]$LauncherResource)
$ErrorActionPreference = 'Stop'
$repoDir = Split-Path $PSScriptRoot -Parent
$assets = Join-Path $repoDir 'ui\DirectLAN\Assets'
Add-Type -AssemblyName PresentationCore,PresentationFramework,WindowsBase
$drawing = [Windows.Markup.XamlReader]::Parse([IO.File]::ReadAllText((Join-Path $assets 'DirectLANMark.xaml')))
$frames = @()
foreach ($size in @(16,20,24,32,40,48,64,128,256)) {
    $visual = [Windows.Media.DrawingVisual]::new()
    $context = $visual.RenderOpen()
    $context.PushTransform([Windows.Media.ScaleTransform]::new($size / 256.0, $size / 256.0))
    $context.DrawDrawing($drawing.Drawing)
    $context.Pop()
    $context.Close()
    $bitmap = [Windows.Media.Imaging.RenderTargetBitmap]::new($size,$size,96,96,[Windows.Media.PixelFormats]::Pbgra32)
    $bitmap.Render($visual)
    $encoder = [Windows.Media.Imaging.PngBitmapEncoder]::new()
    $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
    $stream = [IO.MemoryStream]::new()
    try {
        $encoder.Save($stream)
        $frames += ,@{Size=$size;Data=$stream.ToArray()}
    } finally { $stream.Dispose() }
}
[IO.File]::WriteAllBytes((Join-Path $assets 'DirectLANMark.png'), $frames[-1].Data)
$icon = [IO.MemoryStream]::new()
$writer = [IO.BinaryWriter]::new($icon)
try {
    $writer.Write([uint16]0)
    $writer.Write([uint16]1)
    $writer.Write([uint16]$frames.Count)
    $offset = 6 + 16 * $frames.Count
    foreach ($frame in $frames) {
        $dimension = if ($frame.Size -eq 256) { 0 } else { $frame.Size }
        $writer.Write([byte]$dimension)
        $writer.Write([byte]$dimension)
        $writer.Write([byte]0)
        $writer.Write([byte]0)
        $writer.Write([uint16]1)
        $writer.Write([uint16]32)
        $writer.Write([uint32]$frame.Data.Length)
        $writer.Write([uint32]$offset)
        $offset += $frame.Data.Length
    }
    foreach ($frame in $frames) { $writer.Write([byte[]]$frame.Data) }
    $writer.Flush()
    [IO.File]::WriteAllBytes((Join-Path $assets 'DirectLAN.ico'),$icon.ToArray())
} finally { $writer.Dispose(); $icon.Dispose() }
if ($LauncherResource) {
    $goPath = Join-Path $repoDir '.tools\go\bin\go.exe'
    if (!(Test-Path -LiteralPath $goPath)) { $goPath = (Get-Command go -ErrorAction Stop).Source }
    & $goPath run github.com/akavel/rsrc@v0.10.2 -arch amd64 -ico (Join-Path $assets 'DirectLAN.ico') -o (Join-Path $repoDir 'cmd\directlan-launcher\resource_windows_amd64.syso')
    if ($LASTEXITCODE) { throw 'Launcher icon resource generation failed.' }
}
Write-Host 'Application icon and header mark generated.'
