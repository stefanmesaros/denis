<#
.SYNOPSIS
  Install denis as a Windows Service, from a `denis.exe` you already built or downloaded.

.DESCRIPTION
  UNVERIFIED on a real Windows machine (see WINDOWS.md — this whole script is written against
  documented PowerShell/Windows behaviour, the same honesty bar as every other Windows-only piece
  of this project before it was run for real, not run for real itself yet).

  Unlike packaging/install.sh, this script does **not** download a release: DENIS does not yet
  build or sign a Windows binary in CI (see WINDOWS.md's "genuinely missing" list) — the Npcap SDK
  needed even just to link `denis.exe` is not available in CI yet. Point -ExePath at a `denis.exe`
  you built yourself (`cargo build --release`, see WINDOWS.md's "Verified on a real Windows
  machine" section for exactly how) or downloaded and checked by hand. Once a signed Windows
  release exists, this script should gain the same Ed25519/SHA-256 verification install.sh already
  has for Linux — that is a deliberate gap here, not an oversight.

  What it does:
    1. Copies denis.exe to -InstallDir (default: Program Files\DENIS).
    2. Creates -DataDir (default: ProgramData\DENIS) and restricts it to Administrators and
       SYSTEM only (icacls) — the Windows equivalent of the systemd unit's
       StateDirectoryMode=0700 (SECURITY_ARCHITECTURE_REVIEW.md M10).
    3. Registers the service (`denis.exe service install`) and starts it.
    4. Optionally opens the listen port in Windows Firewall (-OpenFirewall), for a non-loopback
       -Listen address only — never done silently.

.PARAMETER ExePath
  The denis.exe to install. Required unless -Uninstall.

.PARAMETER InstallDir
  Where the program is copied. Default: "$env:ProgramFiles\DENIS".

.PARAMETER DataDir
  Where the database and TLS certificate live. Default: "$env:ProgramData\DENIS".

.PARAMETER Listen
  The web console's listen address, passed straight to `denis run --listen`. Default:
  "127.0.0.1:8443" (loopback only — use an SSH/RDP tunnel, or pass a routable address and
  -OpenFirewall to reach it from the network).

.PARAMETER OpenFirewall
  Add a Windows Firewall rule for -Listen's port. Refused (with a warning) if -Listen is a
  loopback address, since there would be nothing useful to open.

.PARAMETER Uninstall
  Stop and remove the service. -Purge also deletes -DataDir; without it, the database and
  certificate are left in place (the same "keep the data unless told otherwise" default
  install.sh uses).

.EXAMPLE
  .\install.ps1 -ExePath .\target\release\denis.exe -Listen 0.0.0.0:8443 -OpenFirewall

.EXAMPLE
  .\install.ps1 -Uninstall -Purge
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)]
    [string]$ExePath,

    [Parameter(ParameterSetName = 'Install')]
    [string]$InstallDir = "$env:ProgramFiles\DENIS",

    [Parameter(ParameterSetName = 'Install')]
    [Parameter(ParameterSetName = 'Uninstall')]
    [string]$DataDir = "$env:ProgramData\DENIS",

    [Parameter(ParameterSetName = 'Install')]
    [string]$Listen = "127.0.0.1:8443",

    [Parameter(ParameterSetName = 'Install')]
    [switch]$OpenFirewall,

    [Parameter(ParameterSetName = 'Uninstall', Mandatory = $true)]
    [switch]$Uninstall,

    [Parameter(ParameterSetName = 'Uninstall')]
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this from an elevated (Administrator) PowerShell prompt."
    }
}

Assert-Admin

if ($Uninstall) {
    $exe = Join-Path $InstallDir 'denis.exe'
    if (Test-Path $exe) {
        Write-Host "==> Stopping and removing the service"
        & $exe service stop 2>$null
        & $exe service uninstall 2>$null
    } else {
        Write-Warning "denis.exe not found at $exe; attempting to remove the service by name anyway"
        Stop-Service -Name denis -ErrorAction SilentlyContinue
        sc.exe delete denis | Out-Null
    }
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    if ($Purge) {
        Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
        Write-Host "==> Everything removed, including the data in $DataDir."
    } else {
        Write-Host "==> Removed. Your data is still in $DataDir (pass -Purge to delete it too)."
    }
    return
}

if (-not (Test-Path $ExePath)) {
    throw "$ExePath does not exist. Build it first (see WINDOWS.md) or point -ExePath at a denis.exe you already have."
}

Write-Host "==> Installing to $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force $ExePath (Join-Path $InstallDir 'denis.exe')
$exe = Join-Path $InstallDir 'denis.exe'

Write-Host "==> Preparing $DataDir (restricted to Administrators and SYSTEM)"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
# The Windows equivalent of StateDirectoryMode=0700 / UMask=0077 on the systemd units
# (SECURITY_ARCHITECTURE_REVIEW.md M10): the database holds TOTP secrets and every integration
# credential in plaintext settings rows.
icacls $DataDir /inheritance:r | Out-Null
icacls $DataDir /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null

$db = Join-Path $DataDir 'denis.db'
Write-Host "==> Registering the service (listening on $Listen)"
& $exe service install -- --db $db --listen $Listen
& $exe service start

if ($OpenFirewall) {
    $portPart = ($Listen -split ':')[-1]
    $addrPart = $Listen.Substring(0, $Listen.Length - $portPart.Length - 1)
    if ($addrPart -in @('127.0.0.1', 'localhost', '::1')) {
        Write-Warning "-Listen is loopback-only ($Listen): no firewall rule opened, since nothing outside this machine could reach it anyway."
    } else {
        Write-Host "==> Opening TCP $portPart in Windows Firewall"
        New-NetFirewallRule -DisplayName "DENIS ($portPart/tcp)" -Direction Inbound -Protocol TCP -LocalPort $portPart -Action Allow | Out-Null
    }
}

Write-Host ""
Write-Host "==> Installed. The one-time administrator password (if this is a fresh database) is in:"
Write-Host "    $(Join-Path $InstallDir 'service.log')"
Write-Host "==> Open https://$($Listen -replace '^0\.0\.0\.0','localhost') to sign in."
