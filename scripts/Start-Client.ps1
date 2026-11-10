param(
    [Parameter(Mandatory=$true)][string]$Coordinator,
    [Parameter(Mandatory=$true)][string]$CA,
    [ValidateSet('https','auto','direct')][string]$Transport='https',
    [string]$Stun='',
    [switch]$AllowFirewall,
    [switch]$NoPadding
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this test script from PowerShell as Administrator for Wintun.' }
$caPath = (Resolve-Path -LiteralPath $CA).Path
$exe = Join-Path $PSScriptRoot 'directlan-service.exe'
if ($AllowFirewall) {
    $ruleName = 'DirectLAN-Test-Transport'
    if (-not (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $ruleName -DisplayName 'DirectLAN test transport and overlay probe' -Program $exe -Direction Inbound -Protocol UDP -Action Allow | Out-Null
    }
}
$stateDir = Join-Path $env:LOCALAPPDATA 'DirectLAN'
$serviceArgs = @('-coordinator',$Coordinator,'-coordinator-ca',$caPath,'-identity',(Join-Path $stateDir 'identity.dat'),'-transport',$Transport,"-padding=$(!$NoPadding)",'-device-name',$env:COMPUTERNAME)
if ($Stun) { $serviceArgs += @('-stun',$Stun) }
Write-Host 'Open ui\DirectLAN.exe normally (without elevation), then select the physical adapter on both PCs.'
Write-Host 'Stop the service with Ctrl+C.'
& $exe @serviceArgs
