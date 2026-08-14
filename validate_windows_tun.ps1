#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Runs the host-gated Windows native-TUN validation sequence for SHPH.

.DESCRIPTION
    Place this script in the SHPH repository root. Run it from an elevated
    PowerShell session after placing the operator-approved wintun.dll in the
    current directory. This validator verifies its Authenticode signature
    before deployment.

    The script intentionally enables only SHPH's native Wintun backend. It
    does not permit a stub-adapter fallback: missing, untrusted, or unusable
    Wintun causes the validation to fail.

    The final smoke test creates a temporary native adapter, applies a
    reserved benchmark route and temporary DNS server, then verifies SHPH's
    normal in-process rollback and teardown path. It is a single-host
    lifecycle/control-plane check; two-node forwarding and reconnect evidence
    remain separate Phase F release-gate requirements.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-NativeCommand {
    <#
    .SYNOPSIS
        Runs a native executable and converts a nonzero exit code to a
        terminating PowerShell error.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$File,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Write-Host ">> $File $($Arguments -join ' ')"
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $File @Arguments
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    if ($exitCode -ne 0) {
        throw "Command failed with exit code ${exitCode}: $File $($Arguments -join ' ')"
    }
}

# Enforce elevation explicitly as a defense-in-depth check in addition to
# #Requires -RunAsAdministrator. Do not try to self-elevate or continue.
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Administrator elevation is required. Start PowerShell with 'Run as administrator' and rerun this script."
}

# The operator-provided runtime must be located in the caller's current
# directory. Capture that path before moving to the repository root.
$runtimeDirectory = Get-Location
if ($runtimeDirectory.Provider.Name -ne "FileSystem") {
    throw "The current location must be a filesystem directory containing wintun.dll."
}

$wintunSourcePath = Join-Path -Path $runtimeDirectory.Path -ChildPath "wintun.dll"
if (-not (Test-Path -LiteralPath $wintunSourcePath -PathType Leaf)) {
    throw "Required Wintun runtime is missing: $wintunSourcePath"
}

$wintunSourceItem = Get-Item -LiteralPath $wintunSourcePath -Force
if (($wintunSourceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "wintun.dll must be a regular file, not a reparse point: $wintunSourcePath"
}

if ($wintunSourceItem.Length -le 0 -or $wintunSourceItem.Length -gt 64MB) {
    throw "wintun.dll must be a non-empty regular file no larger than 64 MiB."
}

# Verify the deployment artifact before using it. SHPH enforces the
# application-local path and SHA-256 at runtime; this validator additionally
# requires a valid Authenticode signature before staging the DLL.
$wintunSignature = Get-AuthenticodeSignature -LiteralPath $wintunSourcePath
if ($wintunSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "wintun.dll does not have a valid Authenticode signature: $($wintunSignature.Status)"
}

# Pin the exact operator-provided runtime for this process and every child
# process. The SHPH Windows backend rejects missing, malformed, or mismatched
# values, so this hash is never a best-effort diagnostic.
$env:SHPH_WINTUN_SHA256 = (Get-FileHash -LiteralPath $wintunSourcePath -Algorithm SHA256).Hash.ToUpperInvariant()
if ($env:SHPH_WINTUN_SHA256 -notmatch "^[0-9A-F]{64}$") {
    throw "Unable to derive a valid SHA-256 digest for wintun.dll."
}

# Force the real Wintun backend. SHPH must fail explicitly if the runtime,
# adapter creation, or session setup cannot succeed.
$env:SHPH_TUN_NATIVE = "1"

# This script is stored at the repository root. Resolve and validate that root
# so all commands and evidence paths remain reproducible.
$repoRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($repoRoot) -or
    -not (Test-Path -LiteralPath (Join-Path $repoRoot "Cargo.toml") -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $repoRoot "scripts\benchmark_windows.ps1") -PathType Leaf)) {
    throw "Place validate_windows_tun.ps1 in the SHPH repository root and rerun it."
}

# A custom target directory would make the release CLI location ambiguous.
# Refuse it rather than accidentally validating stale or unrelated artifacts.
if (-not [string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
    throw "CARGO_TARGET_DIR must be unset so this script validates repository-local release artifacts."
}

Set-Location -LiteralPath $repoRoot

# Build all Windows workspace artifacts from the locked dependency graph.
Invoke-NativeCommand -File "cargo" -Arguments @(
    "build",
    "--workspace",
    "--release",
    "--locked"
)

# Build the standalone benchmark harness from its own locked dependency graph.
Invoke-NativeCommand -File "cargo" -Arguments @(
    "build",
    "--release",
    "--manifest-path",
    "benchmarks/Cargo.toml",
    "--locked"
)

$shphBinary = Join-Path $repoRoot "target\release\shph.exe"
if (-not (Test-Path -LiteralPath $shphBinary -PathType Leaf)) {
    throw "Compiled release CLI not found: $shphBinary"
}

# The SHPH loader only accepts the application-local filename wintun.dll. Copy
# the already checked and hashed operator artifact beside shph.exe, then verify
# that the deployed bytes still match the exported provenance pin.
$releaseDirectory = Split-Path -Parent $shphBinary
$deployedWintunPath = Join-Path $releaseDirectory "wintun.dll"
Copy-Item -LiteralPath $wintunSourcePath -Destination $deployedWintunPath -Force

$deployedHash = (Get-FileHash -LiteralPath $deployedWintunPath -Algorithm SHA256).Hash.ToUpperInvariant()
if ($deployedHash -cne $env:SHPH_WINTUN_SHA256) {
    throw "Application-local wintun.dll hash differs from SHPH_WINTUN_SHA256."
}

# Capture a fresh, non-overlapping final benchmark bundle. Existing output is
# rejected to prevent evidence from multiple runs being mixed silently.
$benchmarkOutputDirectory = Join-Path $repoRoot "benchmark-runs\windows-native-final"
if (Test-Path -LiteralPath $benchmarkOutputDirectory) {
    throw "Benchmark output already exists: $benchmarkOutputDirectory. Archive or remove it before a fresh final capture."
}

# Use the repository's PowerShell runner and the release-gate workload values.
& .\scripts\benchmark_windows.ps1 `
    -Suite all `
    -Iterations 5000 `
    -Frames 100000 `
    -OutputDirectory .\benchmark-runs\windows-native-final

if (-not $?) {
    throw "The Windows benchmark runner failed."
}

# Confirm that the runner emitted both required profiles rather than merely
# returning without an error.
foreach ($requiredBenchmarkFile in @("secure-default.csv", "classical-lab.csv")) {
    $benchmarkFile = Join-Path $benchmarkOutputDirectory $requiredBenchmarkFile
    if (-not (Test-Path -LiteralPath $benchmarkFile -PathType Leaf) -or
        (Get-Item -LiteralPath $benchmarkFile).Length -le 0) {
        throw "Expected benchmark evidence was not produced: $benchmarkFile"
    }
}

# Use an ephemeral no-session configuration. `shph up` still opens the Wintun
# adapter/session, applies the live control-plane plan, and runs its normal
# cleanup before returning. The RFC 2544 benchmark network avoids routing
# ordinary public traffic during this host-local lifecycle check.
$smokeDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("shph-phase-f-" + [Guid]::NewGuid().ToString("N"))
$smokeConfigPath = Join-Path $smokeDirectory "config.toml"
# SHPH accepts interface names up to 15 bytes. The seven-byte prefix plus an
# eight-character hexadecimal suffix gives each run a unique valid name.
$adapterName = "shph-f-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)

New-Item -ItemType Directory -Path $smokeDirectory -Force | Out-Null

$smokeConfig = @"
interface_name = "$adapterName"
local_endpoint = "127.0.0.1:51820"
peers = []

[control_plane]
apply_routes = true
route_cidrs = ["198.18.0.0/15"]
apply_dns = true
dns_servers = ["1.1.1.1"]
dry_run = false
"@

# Write BOM-free UTF-8 so the Rust TOML parser receives the intended bytes on
# both Windows PowerShell 5.1 and PowerShell 7.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($smokeConfigPath, $smokeConfig, $utf8NoBom)

try {
    # Success proves the native-only Wintun lifecycle and the route/DNS
    # apply-and-rollback path completed. A stub adapter cannot satisfy this.
    Invoke-NativeCommand -File $shphBinary -Arguments @(
        "up",
        "--config",
        $smokeConfigPath
    )
}
catch {
    # `up` normally rolls back before reporting an error. Run `down` as a
    # best-effort safety net if a persisted control-plane state record exists,
    # but preserve the original failure as the gate result.
    try {
        & $shphBinary "--config" $smokeConfigPath "down" | Out-Host
    }
    catch {
        Write-Warning "Emergency control-plane cleanup failed: $($_.Exception.Message)"
    }

    throw
}
finally {
    Remove-Item -LiteralPath $smokeDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Windows native TUN validation completed successfully."
Write-Host "SHPH_TUN_NATIVE=$env:SHPH_TUN_NATIVE"
Write-Host "SHPH_WINTUN_SHA256=$env:SHPH_WINTUN_SHA256"
Write-Host "Benchmark evidence: $benchmarkOutputDirectory"
