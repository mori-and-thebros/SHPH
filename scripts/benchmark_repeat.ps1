[CmdletBinding()]
param(
    [string]$Binary = "",
    [string]$OutputDirectory = ".\benchmark-runs\repeatability",
    [ValidateSet("all", "core", "dataplane", "resource", "shroud", "quic", "scalability", "identity", "wire", "evidence", "extended")]
    [string]$Suite = "extended",
    [ValidateRange(2, 100)]
    [int]$Runs = 5,
    [ValidateRange(1, 10000000)]
    [int]$Iterations = 1000,
    [ValidateRange(1, 100000000)]
    [int]$Frames = 2000
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
    try {
        $null = & $candidatePath --help 2>$null
        if ($LASTEXITCODE -eq 0) {
            $resolvedBinary = $candidatePath
            break
        }
    } catch {
        if ($explicitBinary) {
            throw
        }
    }
}

if ([string]::IsNullOrWhiteSpace($resolvedBinary)) {
    throw "No usable benchmark executable was found. Build the standalone runner before repeating captures."
}

$resolvedOutput = Join-Path $repoRoot $OutputDirectory
New-Item -ItemType Directory -Force -Path $resolvedOutput | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)
$summary = [System.Collections.Generic.List[object]]::new()

for ($run = 1; $run -le $Runs; $run++) {
    $capturePath = Join-Path $resolvedOutput ("run-{0:D2}.txt" -f $run)
    $arguments = @(
        "--profile", "secure-default",
        "--suite", $Suite,
        "--iterations", $Iterations.ToString(),
        "--frames", $Frames.ToString()
    )

    Write-Host "Running $run/$Runs -> $capturePath"
    $lines = @(& $resolvedBinary @arguments 2>&1 | ForEach-Object { $_.ToString() })
    $exitCode = $LASTEXITCODE
    $lines | ForEach-Object { Write-Host $_ }
    [System.IO.File]::WriteAllText(
        $capturePath,
        (($lines -join [Environment]::NewLine) + [Environment]::NewLine),
        $utf8
    )
    if ($exitCode -ne 0) {
        throw "Benchmark run $run exited with code $exitCode"
    }

    $hash = (Get-FileHash -LiteralPath $capturePath -Algorithm SHA256).Hash
    $summary.Add([pscustomobject]@{
        Run = $run
        Capture = Split-Path -Leaf $capturePath
        Sha256 = $hash
        Bytes = (Get-Item -LiteralPath $capturePath).Length
    })
}

$summaryPath = Join-Path $resolvedOutput "summary.csv"
$summary | Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding utf8

Write-Host ""
Write-Host "Repeatability summary:"
$summary | Format-Table -AutoSize
Write-Host "Summary CSV: $summaryPath"
Write-Host "Binary: $resolvedBinary"
Write-Host "Suite: $Suite; iterations: $Iterations; frames: $Frames"
Write-Host "Note: Shroud2 payload padding uses OS randomness, so capture hashes are expected to differ even with fixed benchmark seeds."
