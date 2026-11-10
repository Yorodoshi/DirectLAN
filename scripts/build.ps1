param([string]$GoPath)
$ErrorActionPreference = 'Stop'
$repoDir = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $repoDir
if (-not $GoPath) {
    $GoPath = Join-Path $repoDir '.tools\go\bin\go.exe'
    if (-not (Test-Path -LiteralPath $GoPath)) { $GoPath = (Get-Command go -ErrorAction Stop).Source }
}
if ((& $GoPath version) -notmatch 'go1\.27\.3 ') { throw 'Go 1.27.3 is required for this build.' }
$oldCGO = $env:CGO_ENABLED
try {
    $env:CGO_ENABLED = '0'
    & $GoPath mod verify
    if ($LASTEXITCODE) { throw 'Dependency verification failed.' }
    & $GoPath test ./...
    if ($LASTEXITCODE) { throw 'Go tests failed.' }
    & $GoPath vet ./...
    if ($LASTEXITCODE) { throw 'Go vet failed.' }
    New-Item -ItemType Directory -Force -Path 'bin\licenses' | Out-Null
    foreach ($command in @('directlan-service','directlan-coordinator','directlan-cert')) {
        & $GoPath build -buildvcs=false -trimpath -ldflags '-s -w' -o "bin/$command.exe" "./cmd/$command"
        if ($LASTEXITCODE) { throw "Build failed: $command" }
    }
    & $GoPath build -buildvcs=false -trimpath -ldflags '-s -w -H windowsgui' -o bin/DirectLAN-Start.exe ./cmd/directlan-launcher
    if ($LASTEXITCODE) { throw 'Client launcher build failed.' }
    dotnet publish ui/DirectLAN/DirectLAN.csproj -c Release -r win-x64 --self-contained true -p:ContinuousIntegrationBuild=true -p:DebugType=None -p:DebugSymbols=false -o bin/ui
    if ($LASTEXITCODE) { throw 'WPF publish failed.' }
    $dotnetDirectory = Split-Path (Get-Command dotnet -ErrorAction Stop).Source -Parent
    foreach ($notice in @('LICENSE.txt','ThirdPartyNotices.txt')) {
        Copy-Item -LiteralPath (Join-Path $dotnetDirectory $notice) -Destination (Join-Path 'bin\licenses' ('DotNet-' + $notice)) -Force
    }
    $cacheDir = Join-Path $repoDir '.tools'
    New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
    $archive = Join-Path $cacheDir 'wintun-0.14.1.zip'
    if (-not (Test-Path -LiteralPath $archive)) { Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $archive }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51') { throw 'Wintun checksum mismatch.' }
    $driverDir = Join-Path $cacheDir 'wintun-package'
    Expand-Archive -LiteralPath $archive -DestinationPath $driverDir -Force
    $driver = Join-Path $driverDir 'wintun\bin\amd64\wintun.dll'
    if ((Get-AuthenticodeSignature -LiteralPath $driver).Status -ne 'Valid') { throw 'Wintun signature is not valid.' }
    Copy-Item -LiteralPath $driver -Destination 'bin\wintun.dll' -Force
    Copy-Item -LiteralPath (Join-Path $driverDir 'wintun\LICENSE.txt') -Destination 'bin\licenses\Wintun.txt' -Force
    $modules = & $GoPath list -m -f '{{.Path}}|{{.Version}}|{{.Dir}}' all
    $modules | ForEach-Object { $parts=$_.Split('|'); "$($parts[0]) $($parts[1])" } | Set-Content -LiteralPath 'bin\DEPENDENCIES.txt' -Encoding UTF8
    foreach ($row in $modules) {
        $fields = $row.Split('|')
        if ($fields.Length -lt 3 -or -not $fields[2] -or $fields[0] -eq 'directlan') { continue }
        $label = $fields[0].Replace('/','_')
        foreach ($license in (Get-ChildItem -LiteralPath $fields[2] -File | Where-Object { $_.Name -match '^(LICENSE|COPYING|NOTICE)' })) {
            Copy-Item -LiteralPath $license.FullName -Destination (Join-Path 'bin\licenses' ($label + '-' + $license.Name)) -Force
        }
    }
    Copy-Item -LiteralPath 'docs\QUICKSTART.md' -Destination 'bin\README.md' -Force
    Copy-Item -LiteralPath 'docs\SECURITY.md','docs\TESTING.md' -Destination bin -Force
    Get-ChildItem -LiteralPath bin -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | ForEach-Object { $h = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256; "$($h.Hash.ToLowerInvariant())  $($_.Name)" } | Set-Content -LiteralPath 'bin\SHA256SUMS.txt'
    Write-Host 'Build complete: bin (Windows x64, self-contained WPF UI).'
} finally { $env:CGO_ENABLED = $oldCGO }
