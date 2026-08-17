[CmdletBinding()]
param(
    [string]$OutputDirectory = "benchmark-runs/security-evidence",
    [switch]$AllowDirty,
    [switch]$AllowNetwork,
    [switch]$SkipAudit,
    [switch]$SkipFuzz
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot
Set-Location -LiteralPath $repoRoot

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$resolvedOutput = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory
} else {
    Join-Path $repoRoot $OutputDirectory
}
New-Item -ItemType Directory -Force -Path $resolvedOutput | Out-Null

$logPath = Join-Path $resolvedOutput "security-evidence-$stamp.log"
$reportPath = Join-Path $resolvedOutput "security-evidence-$stamp.md"
$jsonPath = Join-Path $resolvedOutput "security-evidence-$stamp.json"
$results = New-Object System.Collections.Generic.List[object]
$hasIncomplete = $false
$hasFailure = $false

function Write-RunLog {
    param([Parameter(Mandatory = $true)][string]$Line)

    $safeLine = $Line.Replace($repoRoot, "<repository>")
    Add-Content -LiteralPath $logPath -Value $safeLine
    Write-Host $safeLine
}

function Add-Result {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][ValidateSet("PASS", "FAIL", "SKIP", "WARN")][string]$Status,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string]$Detail
    )

    $results.Add([pscustomobject]@{
        id = $Id
        status = $Status
        command = $Command
        detail = $Detail
    })
    if ($Status -eq "FAIL") {
        $script:hasFailure = $true
    }
    if ($Status -ne "PASS") {
        $script:hasIncomplete = $true
    }
}

function Invoke-Gate {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    Write-RunLog ">>> $Id :: $Command"
    $output = @()
    $exitCode = 1
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = @(& $Action 2>&1)
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    } catch {
        $output = @($_.Exception.Message)
        $exitCode = 1
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    foreach ($line in $output) {
        Write-RunLog ("  " + $line.ToString())
    }
    if ($exitCode -eq 0) {
        Add-Result -Id $Id -Status "PASS" -Command $Command -Detail "exit 0"
    } else {
        Add-Result -Id $Id -Status "FAIL" -Command $Command -Detail "exit $exitCode"
    }
}

function Invoke-CargoGate {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][object[]]$Arguments
    )

    $commandText = "cargo " + (($Arguments | ForEach-Object { $_.ToString() }) -join " ")
    Invoke-Gate -Id $Id -Command $commandText -Action {
        & cargo @Arguments
    }
}

Write-RunLog "# SHPH security-evidence collector"
Write-RunLog "generated_utc=$((Get-Date).ToUniversalTime().ToString("o"))"
Write-RunLog "allow_dirty=$AllowDirty"
Write-RunLog "allow_network=$AllowNetwork"

$git = Get-Command git -ErrorAction SilentlyContinue
if ($null -eq $git) {
    Add-Result -Id "git-available" -Status "FAIL" -Command "git" -Detail "git is not available"
} else {
    $dirty = @(& git status --porcelain 2>&1)
    if ($dirty.Count -eq 0) {
        Add-Result -Id "clean-tree" -Status "PASS" -Command "git status --porcelain" -Detail "clean"
    } elseif ($AllowDirty) {
        Add-Result -Id "clean-tree" -Status "WARN" -Command "git status --porcelain" `
            -Detail "dirty tree allowed for engineering evidence only"
        foreach ($line in $dirty) {
            Write-RunLog ("  dirty: " + $line.ToString())
        }
    } else {
        Add-Result -Id "clean-tree" -Status "FAIL" -Command "git status --porcelain" `
            -Detail "dirty tree; use -AllowDirty only for non-release evidence"
    }
    Write-RunLog ">>> diff-check :: git diff --check"
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $diffOutput = @(& git diff --check 2>&1)
        $diffExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    foreach ($line in $diffOutput) {
        Write-RunLog ("  " + $line.ToString())
    }
    if ($diffExitCode -eq 0) {
        Add-Result -Id "diff-check" -Status "PASS" -Command "git diff --check" -Detail "exit 0"
    } else {
        Add-Result -Id "diff-check" -Status "FAIL" -Command "git diff --check" -Detail "exit $diffExitCode"
    }
}

$rg = Get-Command rg -ErrorAction SilentlyContinue
if ($null -eq $rg) {
    Add-Result -Id "secret-material-scan" -Status "SKIP" -Command "rg secret-material scan" `
        -Detail "ripgrep is not available"
} else {
    $pattern = "BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{20,}"
    $scanArguments = @(
        "-n", "--hidden",
        "-g", "!target/**",
        "-g", "!benchmark-runs/**",
        "-g", "!*.lock",
        $pattern,
        "."
    )
    Write-RunLog ">>> secret-material-scan :: rg $pattern ."
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $scanOutput = @(& rg @scanArguments 2>&1)
        $scanExit = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    foreach ($line in $scanOutput) {
        Write-RunLog ("  " + $line.ToString())
    }
    if ($scanExit -eq 1) {
        Add-Result -Id "secret-material-scan" -Status "PASS" -Command "rg private-key/token markers" `
            -Detail "no common markers found"
    } elseif ($scanExit -eq 0) {
        Add-Result -Id "secret-material-scan" -Status "FAIL" -Command "rg private-key/token markers" `
            -Detail "possible secret material found; review output before publication"
    } else {
        Add-Result -Id "secret-material-scan" -Status "FAIL" -Command "rg private-key/token markers" `
            -Detail "scanner exited $scanExit"
    }
}

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -eq $cargo) {
    Add-Result -Id "cargo-available" -Status "FAIL" -Command "cargo" -Detail "cargo is not available"
} else {
    $cargoFlags = @("--locked")
    if (-not $AllowNetwork) {
        $cargoFlags += "--offline"
    }
    Invoke-Gate -Id "fmt" -Command "cargo fmt --all -- --check" -Action {
        & cargo fmt --all -- --check
    }
    Invoke-CargoGate -Id "metadata" -Arguments (@("metadata", "--format-version", "1", "--no-deps") + $cargoFlags)
    Invoke-CargoGate -Id "core-tests" -Arguments (@("test", "-p", "shph-core", "--lib") + $cargoFlags)
    Invoke-CargoGate -Id "transport-tests" -Arguments (@("test", "-p", "shph-transport", "--lib") + $cargoFlags)
    Invoke-CargoGate -Id "tun-tests" -Arguments (@("test", "-p", "shph-tun", "--lib") + $cargoFlags)

    if ($SkipAudit) {
        Add-Result -Id "cargo-audit" -Status "SKIP" -Command "cargo audit --deny warnings" `
            -Detail "explicitly skipped"
    } elseif ($null -eq (Get-Command cargo-audit -ErrorAction SilentlyContinue)) {
        Add-Result -Id "cargo-audit" -Status "SKIP" -Command "cargo audit --deny warnings" `
            -Detail "cargo-audit is not installed"
    } else {
        Invoke-CargoGate -Id "cargo-audit" -Arguments @("audit", "--deny", "warnings")
    }
}

if ($SkipFuzz) {
    Add-Result -Id "fuzz-smoke" -Status "SKIP" -Command "cargo fuzz smoke" -Detail "explicitly skipped"
} elseif ($null -eq (Get-Command cargo-fuzz -ErrorAction SilentlyContinue)) {
    Add-Result -Id "fuzz-smoke" -Status "SKIP" -Command "cargo fuzz smoke" `
        -Detail "cargo-fuzz is not installed"
} else {
    $nightly = @(& rustup toolchain list 2>&1 | ForEach-Object { $_.ToString() })
    if (-not ($nightly -match "nightly-2026-07-16")) {
        Add-Result -Id "fuzz-smoke" -Status "SKIP" -Command "rustup toolchain list" `
            -Detail "nightly-2026-07-16 is not installed"
    } else {
        $targets = @("frame_decode", "config_parse", "audit_record", "replay_window", "shroud2_datagram")
        foreach ($target in $targets) {
            $targetName = "fuzz-$target"
            Invoke-Gate -Id $targetName `
                -Command "cargo +nightly-2026-07-16 fuzz run $target -- -runs=1" -Action {
                Push-Location -LiteralPath (Join-Path $repoRoot "fuzz")
                try {
                    & cargo +nightly-2026-07-16 fuzz run $target -- -runs=1
                } finally {
                    Pop-Location
                }
            }
        }
    }
}

$reportLines = @(
    "# SHPH Security Evidence Result",
    "",
    "Generated: $((Get-Date).ToUniversalTime().ToString("o"))",
    "",
    "| ID | Status | Command | Detail |",
    "| --- | --- | --- | --- |"
)
foreach ($result in $results) {
    $command = $result.command.Replace("|", "\|")
    $detail = $result.detail.Replace("|", "\|")
    $reportLines += "| $($result.id) | $($result.status) | $command | $detail |"
}
$reportLines | Set-Content -LiteralPath $reportPath -Encoding utf8
($results | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $jsonPath -Encoding utf8
Write-RunLog "report=$reportPath"
Write-RunLog "json=$jsonPath"

if ($hasFailure -or $hasIncomplete) {
    exit 1
}
exit 0
