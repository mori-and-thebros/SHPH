[CmdletBinding()]
param(
    [string]$Binary = "",
    [string]$OutputDirectory = ".\benchmark-runs\windows",
    [ValidateSet("all", "core", "dataplane", "resource", "shroud", "quic", "scalability", "identity", "wire")]
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
$explicitBinary = -not [string]::IsNullOrWhiteSpace($Binary)

if ($explicitBinary) {
    $candidates = @($Binary)
} else {
    $candidates = @(
        (Join-Path $repoRoot "benchmarks\target\release\shph-benchmarks.exe"),
        (Join-Path $repoRoot "benchmarks\target\x86_64-pc-windows-msvc\release\shph-benchmarks.exe"),
        (Join-Path $repoRoot "benchmarks\target\x86_64-pc-windows-gnu\release\shph-benchmarks.exe"),
        (Join-Path $repoRoot "target\release\shph-benchmarks.exe"),
        (Join-Path $repoRoot "target\x86_64-pc-windows-gnu\release\shph-benchmarks.exe")
    )
}

$resolvedBinary = $null
foreach ($candidate in $candidates) {
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        continue
    }

    $candidatePath = (Resolve-Path -LiteralPath $candidate).Path
    $startupExitCode = -1
    try {
        $null = & $candidatePath --help 2>$null
        $startupExitCode = $LASTEXITCODE
    } catch {
        $startupExitCode = -1
    }

    if ($startupExitCode -eq 0) {
        $resolvedBinary = $candidatePath
        break
    }

    if ($explicitBinary) {
        throw "Benchmark executable failed its startup probe with exit code ${startupExitCode}: $candidatePath. Rebuild with the MSVC target or a supported, fully configured LLVM-MinGW toolchain; do not use -C link-self-contained=yes."
    }

    Write-Warning "Skipping benchmark executable that failed its startup probe with exit code ${startupExitCode}: $candidatePath"
}

if ([string]::IsNullOrWhiteSpace($resolvedBinary)) {
    if ($explicitBinary -and
        -not (Test-Path -LiteralPath $candidates[0] -PathType Leaf)) {
        throw "Benchmark executable not found: $($candidates[0]). Build it with: cargo +1.96.0 build --release --manifest-path benchmarks/Cargo.toml --target x86_64-pc-windows-msvc --locked"
    }

    throw "No usable benchmark executable was found. Build it with: cargo +1.96.0 build --release --manifest-path benchmarks/Cargo.toml --target x86_64-pc-windows-msvc --locked"
}

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
