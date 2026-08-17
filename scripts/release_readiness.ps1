[CmdletBinding()]
param(
    [string]$OutputDirectory = "benchmark-runs/release-readiness",
    [switch]$AllowDirty,
    [switch]$AllowNetwork,
    [switch]$SkipBuild,
    [switch]$SkipTests,
    [switch]$SkipAudit,
    [switch]$SkipNative
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

$logPath = Join-Path $resolvedOutput "release-readiness-$stamp.log"
$reportPath = Join-Path $resolvedOutput "release-readiness-$stamp.md"
$jsonPath = Join-Path $resolvedOutput "release-readiness-$stamp.json"
$results = New-Object System.Collections.Generic.List[object]
$hasFailure = $false
$hasIncomplete = $false

function Write-RunLog {
    param([Parameter(Mandatory = $true)][string]$Line)

    $safeLine = $Line.Replace($repoRoot, "<repository>")
    Add-Content -LiteralPath $logPath -Value $safeLine
    Write-Host $safeLine
}

function Add-Result {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][ValidateSet("PASS", "FAIL", "SKIP", "BLOCKED", "WARN")][string]$Status,
        [Parameter(Mandatory = $true)][ValidateSet("required", "host", "provenance")][string]$Class,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string]$Detail
    )

    $results.Add([pscustomobject]@{
        id = $Id
        status = $Status
        class = $Class
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
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [ValidateSet("required", "host", "provenance")][string]$Class = "required"
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
        Add-Result -Id $Id -Status "PASS" -Class $Class -Command $Command -Detail "exit 0"
    } else {
        Add-Result -Id $Id -Status "FAIL" -Class $Class -Command $Command -Detail "exit $exitCode"
    }
}

function Add-SyntheticResult {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][ValidateSet("PASS", "FAIL", "SKIP", "BLOCKED", "WARN")][string]$Status,
        [Parameter(Mandatory = $true)][ValidateSet("required", "host", "provenance")][string]$Class,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string]$Detail
    )

    Write-RunLog ">>> $Id :: $Status :: $Detail"
    Add-Result -Id $Id -Status $Status -Class $Class -Command $Command -Detail $Detail
}

function Join-CommandArguments {
    param([Parameter(Mandatory = $true)][object[]]$Arguments)

    return (($Arguments | ForEach-Object { $_.ToString() }) -join " ")
}

function Invoke-CargoGate {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][object[]]$Arguments,
        [ValidateSet("required", "host", "provenance")][string]$Class = "required"
    )

    $cargoCommandArguments = @("cargo") + $Arguments
    $commandText = Join-CommandArguments -Arguments $cargoCommandArguments
    Invoke-Gate -Id $Id -Command $commandText -Class $Class -Action {
        & cargo @Arguments
    }
}

Write-RunLog "# SHPH release-readiness collector"
Write-RunLog "generated_utc=$((Get-Date).ToUniversalTime().ToString("o"))"
Write-RunLog "repository=$repoRoot"
Write-RunLog "allow_dirty=$AllowDirty"
Write-RunLog "allow_network=$AllowNetwork"

$gitCommand = Get-Command git -ErrorAction SilentlyContinue
if ($null -eq $gitCommand) {
    Add-SyntheticResult -Id "git-available" -Status "FAIL" -Class "provenance" `
        -Command "git" -Detail "git is not available"
} else {
    $dirtyLines = @(& git status --porcelain 2>&1)
    if ($dirtyLines.Count -eq 0) {
        Add-SyntheticResult -Id "clean-tree" -Status "PASS" -Class "provenance" `
            -Command "git status --porcelain" -Detail "clean"
    } elseif ($AllowDirty) {
        Add-SyntheticResult -Id "clean-tree" -Status "WARN" -Class "provenance" `
            -Command "git status --porcelain" -Detail "dirty tree allowed for engineering evidence only"
        foreach ($line in $dirtyLines) {
            Write-RunLog ("  dirty: " + $line.ToString())
        }
    } else {
        Add-SyntheticResult -Id "clean-tree" -Status "FAIL" -Class "provenance" `
            -Command "git status --porcelain" -Detail "dirty tree; use -AllowDirty only for non-release evidence"
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
        Add-Result -Id "diff-check" -Status "PASS" -Class "provenance" `
            -Command "git diff --check" -Detail "exit 0"
    } else {
        Add-Result -Id "diff-check" -Status "FAIL" -Class "provenance" `
            -Command "git diff --check" -Detail "exit $diffExitCode"
    }
    Invoke-Gate -Id "provenance" -Command "rustc -Vv; cargo -V" -Class "provenance" -Action {
        & rustc -Vv
        & cargo -V
    }
}

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -eq $cargo) {
    Add-SyntheticResult -Id "cargo-available" -Status "FAIL" -Class "required" `
        -Command "cargo" -Detail "cargo is not available"
} else {
    $cargoFlags = @("--locked")
    if (-not $AllowNetwork) {
        $cargoFlags += "--offline"
    }

    Invoke-Gate -Id "fmt" -Command "cargo fmt --all -- --check" -Action {
        & cargo fmt --all -- --check
    }
    Invoke-CargoGate -Id "metadata" -Arguments (@("metadata", "--format-version", "1", "--no-deps") + $cargoFlags)
    Invoke-CargoGate -Id "workspace-check" -Arguments (@("check", "--workspace", "--all-targets") + $cargoFlags)
    Invoke-CargoGate -Id "workspace-clippy" -Arguments (@("clippy", "--workspace", "--all-targets") + $cargoFlags + @("--", "-D", "warnings"))

    if ($SkipTests) {
        Add-SyntheticResult -Id "workspace-tests" -Status "SKIP" -Class "required" `
            -Command "cargo test --workspace --all-targets" -Detail "explicitly skipped"
    } else {
        Invoke-CargoGate -Id "workspace-tests" -Arguments (@("test", "--workspace", "--all-targets") + $cargoFlags)
    }

    if ($SkipBuild) {
        Add-SyntheticResult -Id "workspace-release-build" -Status "SKIP" -Class "required" `
            -Command "cargo build --workspace --release" -Detail "explicitly skipped"
    } else {
        Invoke-CargoGate -Id "workspace-release-build" -Arguments (@("build", "--workspace", "--release") + $cargoFlags)
    }

    Invoke-CargoGate -Id "benchmark-manifest" -Arguments (@("check", "--manifest-path", "benchmarks/Cargo.toml", "--all-targets") + $cargoFlags)
    Invoke-CargoGate -Id "fuzz-manifest" -Arguments (@("check", "--manifest-path", "fuzz/Cargo.toml", "--all-targets") + $cargoFlags)

    if ($SkipAudit) {
        Add-SyntheticResult -Id "cargo-audit" -Status "SKIP" -Class "required" `
            -Command "cargo audit --deny warnings" -Detail "explicitly skipped"
    } elseif ($null -eq (Get-Command cargo-audit -ErrorAction SilentlyContinue)) {
        Add-SyntheticResult -Id "cargo-audit" -Status "SKIP" -Class "required" `
            -Command "cargo audit --deny warnings" -Detail "cargo-audit is not installed"
    } else {
        Invoke-CargoGate -Id "cargo-audit" -Arguments @("audit", "--deny", "warnings")
    }
}

$isWindowsHost = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
if ($SkipNative) {
    Add-SyntheticResult -Id "native-host-toolchain" -Status "SKIP" -Class "host" `
        -Command "native host preflight" -Detail "explicitly skipped"
} elseif ($isWindowsHost) {
    $linker = Get-Command link.exe -ErrorAction SilentlyContinue
    if ($null -eq $linker) {
        Add-SyntheticResult -Id "native-host-toolchain" -Status "SKIP" -Class "host" `
            -Command "Get-Command link.exe" -Detail "MSVC link.exe is unavailable"
    } else {
        Add-SyntheticResult -Id "native-host-toolchain" -Status "PASS" -Class "host" `
            -Command "Get-Command link.exe" -Detail $linker.Source
    }
} else {
    Add-SyntheticResult -Id "native-host-toolchain" -Status "SKIP" -Class "host" `
        -Command "native host preflight" -Detail "run the Linux host campaign from a native Linux environment"
}

Add-SyntheticResult -Id "native-tun-two-host" -Status "SKIP" -Class "host" `
    -Command "native TUN packet and two-host campaign" `
    -Detail "requires a dedicated privileged Linux or Windows operator campaign; see docs/RELEASE_READINESS.md"

$releaseEligible = -not $hasIncomplete
$reportLines = @(
    "# SHPH Release-Readiness Result",
    "",
    "Generated: $((Get-Date).ToUniversalTime().ToString("o"))",
    "Release eligible: **$releaseEligible**",
    "",
    "| ID | Status | Class | Command | Detail |",
    "| --- | --- | --- | --- | --- |"
)
foreach ($result in $results) {
    $command = $result.command.Replace("|", "\|")
    $detail = $result.detail.Replace("|", "\|")
    $reportLines += "| $($result.id) | $($result.status) | $($result.class) | $command | $detail |"
}
$reportLines | Set-Content -LiteralPath $reportPath -Encoding utf8
($results | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $jsonPath -Encoding utf8
Write-RunLog "report=$reportPath"
Write-RunLog "json=$jsonPath"
Write-RunLog "release_eligible=$releaseEligible"

if ($hasFailure) {
    exit 1
}
if (-not $releaseEligible) {
    exit 1
}
exit 0
