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
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

$logPath = Join-Path $outputPath "criterion.log"
$metadataPath = Join-Path $outputPath "metadata.txt"
$utf8 = New-Object System.Text.UTF8Encoding($false)
$rustcVersion = (& rustc "+$Toolchain" --version).ToString()

$metadata = @(
    "commit=$(& git -C $repoRoot rev-parse HEAD)"
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
    $lines = @(& cargo @arguments 2>&1 | ForEach-Object { $_.ToString() })
    $exitCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $savedErrorActionPreference
}
$lines | ForEach-Object { Write-Host $_ }
[System.IO.File]::WriteAllLines($logPath, $lines, $utf8)

if ($exitCode -ne 0) {
    throw "Criterion benchmark suite failed with exit code $exitCode. See $logPath"
}

$criterionSource = Join-Path $repoRoot "benchmarks\target\criterion"
$criterionDestination = Join-Path $outputPath "criterion-report"
if (Test-Path -LiteralPath $criterionSource -PathType Container) {
    Copy-Item -LiteralPath $criterionSource -Destination $criterionDestination -Recurse -Force
} else {
    throw "Criterion did not produce its report directory: $criterionSource"
}

Write-Host "Criterion capture complete: $outputPath"
