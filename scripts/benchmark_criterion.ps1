[CmdletBinding()]
param(
    [string]$OutputDirectory = ".\benchmark-runs\criterion-windows",
    [string]$Toolchain = "1.96.0",
    [string]$Filter = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot
$outputPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDirectory))
if (Test-Path -LiteralPath $outputPath) {
    throw "Benchmark output already exists; choose a new output directory: $outputPath"
}

$logPath = Join-Path $outputPath "criterion.log"
$metadataPath = Join-Path $outputPath "metadata.txt"
$utf8 = New-Object System.Text.UTF8Encoding($false)
$rustcVersion = (& rustc "+$Toolchain" --version).ToString()
$previousTargetDirectory = $env:CARGO_TARGET_DIR
$treeState = "clean"
$statusOutput = @(& git -C $repoRoot status --porcelain=v1 --untracked-files=all)
if ($statusOutput.Count -gt 0) {
    $treeState = "dirty"
}
$trackedDiff = (& git -C $repoRoot diff --binary HEAD -- .) -join "`n"
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$trackedDiffHash = [System.BitConverter]::ToString($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($trackedDiff))).Replace("-", "").ToLowerInvariant()
$untrackedPaths = @(& git -C $repoRoot ls-files --others --exclude-standard)
$untrackedInventory = foreach ($path in $untrackedPaths) {
    "$path=$((Get-FileHash -LiteralPath (Join-Path $repoRoot $path) -Algorithm SHA256).Hash.ToLowerInvariant())"
}
$untrackedInventoryHash = [System.BitConverter]::ToString($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($untrackedInventory -join "`n")))).Replace("-", "").ToLowerInvariant()
$sha256.Dispose()
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

$metadata = @(
    "commit=$(& git -C $repoRoot rev-parse HEAD)"
    "tree_state=$treeState"
    "tracked_diff_sha256=$trackedDiffHash"
    "untracked_inventory_sha256=$untrackedInventoryHash"
    "platform=$([System.Environment]::OSVersion.VersionString)"
    "processor=$([System.Environment]::GetEnvironmentVariable('PROCESSOR_IDENTIFIER'))"
    "rustc=$rustcVersion"
    "toolchain=$Toolchain"
    "harness=criterion"
    "scope=local-microbenchmark;GitHub-hosted-run"
    "determinism=inputs-and-seeds-fixed;OS-randomized-padding-may-vary"
)
[System.IO.File]::WriteAllLines($metadataPath, $metadata, $utf8)

$arguments = @(
    "+$Toolchain",
    "bench",
    "--manifest-path", (Join-Path $repoRoot "benchmarks\Cargo.toml"),
    "--bench", "criterion",
    "--locked",
    "--",
    "--noplot"
)
if (-not [string]::IsNullOrWhiteSpace($Filter)) {
    $arguments += $Filter
}

Write-Host "Running Criterion benchmark suite"
Write-Host "Output: $outputPath"
$savedErrorActionPreference = $ErrorActionPreference
try {
    # Cargo writes normal compiler diagnostics to stderr. PowerShell 5 can
    # promote those native stderr records to terminating errors when
    # ErrorActionPreference is Stop, even when cargo exits successfully.
    $ErrorActionPreference = "Continue"
    $env:CARGO_TARGET_DIR = Join-Path $outputPath ".cargo-target"
    $lines = @(& cargo @arguments 2>&1 | ForEach-Object { $_.ToString() })
    $exitCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $savedErrorActionPreference
    if ([string]::IsNullOrEmpty($previousTargetDirectory)) {
        Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
    } else {
        $env:CARGO_TARGET_DIR = $previousTargetDirectory
    }
}
$lines | ForEach-Object { Write-Host $_ }
[System.IO.File]::WriteAllLines($logPath, $lines, $utf8)

if ($exitCode -ne 0) {
    throw "Criterion benchmark suite failed with exit code $exitCode. See $logPath"
}

$criterionSource = Join-Path $outputPath ".cargo-target\criterion"
$criterionDestination = Join-Path $outputPath "criterion-report"
if (Test-Path -LiteralPath $criterionSource -PathType Container) {
    Copy-Item -LiteralPath $criterionSource -Destination $criterionDestination -Recurse -Force
    Remove-Item -LiteralPath (Join-Path $outputPath ".cargo-target") -Recurse -Force
} else {
    throw "Criterion did not produce its report directory: $criterionSource"
}

Write-Host "Criterion capture complete: $outputPath"
