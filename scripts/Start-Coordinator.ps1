param([int]$Port=4433,[switch]$AllowLanFirewall)
$ErrorActionPreference = 'Stop'
$serverDir = Join-Path $PSScriptRoot 'test-server'
$exe = Join-Path $PSScriptRoot 'directlan-coordinator.exe'
if (-not (Test-Path -LiteralPath (Join-Path $serverDir 'server.pem'))) { throw 'Run Prepare-LanTest.ps1 first.' }
if ($AllowLanFirewall) {
    $ruleName = 'DirectLAN-Test-Coordinator'
    if (-not (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $ruleName -DisplayName 'DirectLAN LAN test coordinator' -Program $exe -Direction Inbound -Protocol TCP -LocalPort $Port -RemoteAddress LocalSubnet -Action Allow | Out-Null
    }
}
Write-Host "Coordinator and HTTPS relay on port $Port. Stop with Ctrl+C."
& $exe -listen ":$Port" -state (Join-Path $serverDir 'coordinator.json') -tls-cert (Join-Path $serverDir 'server.pem') -tls-key (Join-Path $serverDir 'server-key.pem') -https-relay
