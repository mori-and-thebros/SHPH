[CmdletBinding()]
param(
    [string]$Binary = "",
    [string]$OutputDirectory = ".\benchmark-runs\windows",
    [ValidateSet("all", "core", "dataplane", "resource", "shroud", "quic", "scalability")]
    [string]$Suite = "all",
    [ValidateRange(1, 10000000)]
    [int]$Iterations = 5000,
    [ValidateRange(1, 100000000)]
    [int]$Frames = 100000,
    [switch]$SkipClassicalLab
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot

if ([string]::IsNullOrWhiteSpace($Binary)) {
    $candidates = @(
        (Join-Path $repoRoot "benchmarks\target\release\shph-benchmarks.exe"),
        (Join-Path $repoRoot "target\release\shph-benchmarks.exe"),
        (Join-Path $repoRoot "target\x86_64-pc-windows-gnu\release\shph-benchmarks.exe")
    )
    $Binary = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}

if ([string]::IsNullOrWhiteSpace($Binary) -or
    -not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "Benchmark executable not found. Build it with: cargo build --release --manifest-path benchmarks/Cargo.toml --locked"
}

$resolvedBinary = (Resolve-Path -LiteralPath $Binary).Path
$resolvedOutput = Join-Path $repoRoot $OutputDirectory
New-Item -ItemType Directory -Force -Path $resolvedOutput | Out-Null

function Invoke-BenchmarkProfile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Profile
    )

    $outputPath = Join-Path $resolvedOutput "$Profile.csv"
    $arguments = @(
        "--profile", $Profile,
        "--suite", $Suite,
        "--iterations", $Iterations.ToString(),
        "--frames", $Frames.ToString()
    )

    Write-Host "Running $Profile -> $outputPath"
    $lines = @(& $resolvedBinary @arguments 2>&1 | ForEach-Object {
        $_.ToString()
    })
    $exitCode = $LASTEXITCODE
    $lines | ForEach-Object { Write-Host $_ }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText(
        $outputPath,
        (($lines -join [Environment]::NewLine) + [Environment]::NewLine),
        $utf8
    )
    if ($exitCode -ne 0) {
        throw "Benchmark profile '$Profile' exited with code $exitCode"
    }
}

Write-Host "SHPH Windows benchmark"
Write-Host "Binary: $resolvedBinary"
Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"
Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
Write-Host "Processor: $([System.Environment]::GetEnvironmentVariable('PROCESSOR_IDENTIFIER'))"
Write-Host "Suite: $Suite; iterations: $Iterations; frames: $Frames"
Write-Host "Native TUN is not enabled by this local benchmark; use a prepared elevated"
Write-Host "two-host configuration for Wintun/TUN throughput and RTT evidence."

Invoke-BenchmarkProfile -Profile "secure-default"
if (-not $SkipClassicalLab) {
    Invoke-BenchmarkProfile -Profile "classical-lab"
}

Write-Host "Benchmark capture complete: $resolvedOutput"
