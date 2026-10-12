[CmdletBinding()]
param(
    [ValidateRange(1, 100000000)]
    [int]$RunsPerTarget = 20000000,
    [string]$OutputDirectory = ".\benchmark-runs\fuzz-campaign",
    [string]$NightlyToolchain = "nightly-2026-07-16",
    [string]$AsanRuntimeDirectory = "",
    [switch]$Resume
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot
$fuzzRoot = Join-Path $repoRoot "fuzz"
Set-Location -LiteralPath $fuzzRoot

$targets = @(
    "frame_decode",
    "config_parse",
    "audit_record",
    "replay_window",
    "shroud2_datagram",
    "phantom_one_envelope",
    "snap_profile"
)

$resolvedOutput = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory
} else {
    Join-Path $repoRoot $OutputDirectory
}
New-Item -ItemType Directory -Force -Path $resolvedOutput | Out-Null

if ([string]::IsNullOrWhiteSpace($AsanRuntimeDirectory)) {
    $asan = Get-ChildItem `
        "C:\Program Files (x86)\Microsoft Visual Studio" `
        -Recurse `
        -Filter "clang_rt.asan_dynamic-x86_64.dll" `
        -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $asan) {
        $AsanRuntimeDirectory = $asan.DirectoryName
    }
}

if (-not [string]::IsNullOrWhiteSpace($AsanRuntimeDirectory)) {
    $env:PATH = "$AsanRuntimeDirectory;$env:PATH"
}

$rustup = Get-Command rustup -ErrorAction SilentlyContinue
$cargoFuzz = Get-Command cargo-fuzz -ErrorAction SilentlyContinue
if ($null -eq $rustup -or $null -eq $cargoFuzz) {
    throw "rustup and cargo-fuzz are required"
}

$toolchain = @(& rustup toolchain list 2>&1 | ForEach-Object { $_.ToString() })
if (-not ($toolchain -match [regex]::Escape($NightlyToolchain))) {
    throw "required toolchain is not installed: $NightlyToolchain"
}

$summaryPath = Join-Path $resolvedOutput "summary.csv"
$summary = New-Object System.Collections.Generic.List[string]
$summary.Add("target,runs,status,elapsed_seconds,log")
$failures = 0

foreach ($target in $targets) {
    $logPath = Join-Path $resolvedOutput "$target.log"
    if ($Resume -and (Test-Path -LiteralPath $logPath)) {
        $completedMarker = "Done $RunsPerTarget runs in"
        $logText = Get-Content -LiteralPath $logPath -Raw -ErrorAction SilentlyContinue
        if ($logText -match [regex]::Escape($completedMarker)) {
            $summary.Add("$target,$RunsPerTarget,PASS,existing,$([System.IO.Path]::GetFileName($logPath))")
            Write-Host "$target`: PASS (existing completed log)"
            continue
        }
    }
    $started = Get-Date
    Write-Host "Running $target for $RunsPerTarget executions"
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $lines = @(
            & cargo "+$NightlyToolchain" fuzz run $target -- "-runs=$RunsPerTarget" 2>&1 |
                ForEach-Object { $_.ToString() }
        )
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $lines | Set-Content -LiteralPath $logPath -Encoding utf8
    $elapsed = ((Get-Date) - $started).TotalSeconds
    $status = if ($exitCode -eq 0) { "PASS" } else { "FAIL" }
    if ($exitCode -ne 0) {
        $failures++
    }
    $summary.Add("$target,$RunsPerTarget,$status,$("{0:N3}" -f $elapsed),$([System.IO.Path]::GetFileName($logPath))")
    Write-Host "$target`: $status ($("{0:N1}" -f $elapsed)s)"
}

$summary | Set-Content -LiteralPath $summaryPath -Encoding utf8
$totalRuns = [int64]$RunsPerTarget * $targets.Count
Write-Host "Total requested executions: $totalRuns"
Write-Host "Summary: $summaryPath"

if ($failures -ne 0) {
    exit 1
}
