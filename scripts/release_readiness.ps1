[CmdletBinding()]
param(
    [string]$OutputDirectory = "benchmark-runs/release-readiness",
    [switch]$AllowDirty,
    [switch]$AllowNetwork,
    [switch]$SkipBuild,
    [switch]$SkipTests,
    [switch]$SkipAudit,
    [switch]$SkipNative,
    [switch]$SkipBenchmarks,
    [switch]$SkipFuzzSmoke,
    [switch]$SkipPackaging,
    [switch]$SkipHttp3,
    [ValidateRange(1, 1000000)]
    [int]$BenchmarkIterations = 3,
    [ValidateRange(1, 10000000)]
    [int]$BenchmarkFrames = 512,
    [ValidateRange(1, 1000000)]
    [int]$FuzzRuns = 1,
    [string]$FuzzToolchain = "nightly-2026-07-16"
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
$repoRootForward = $repoRoot.Replace("\", "/")
$repoRootEscaped = $repoRoot.Replace("\", "\\")
$repoRootEncoded = [System.Uri]::EscapeUriString($repoRootForward)
$repoRootVariants = @(
    $repoRoot,
    $repoRootForward,
    $repoRootEscaped,
    $repoRootEncoded
) | Sort-Object Length -Descending -Unique

function Write-RunLog {
    param([Parameter(Mandatory = $true)][string]$Line)

    $safeLine = $Line
    foreach ($pathVariant in $repoRootVariants) {
        if (-not [string]::IsNullOrWhiteSpace($pathVariant)) {
            $safeLine = $safeLine.Replace($pathVariant, "<repository>")
        }
    }
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
        [ValidateSet("required", "host", "provenance")][string]$Class = "required",
        [string]$WorkingDirectory = "."
    )

    $cargoCommandArguments = @("cargo") + $Arguments
    $commandText = Join-CommandArguments -Arguments $cargoCommandArguments
    if ($WorkingDirectory -ne ".") {
        $commandText = "pushd $WorkingDirectory; $commandText"
    }
    $workingDirectoryPath = if ([System.IO.Path]::IsPathRooted($WorkingDirectory)) {
        $WorkingDirectory
    } else {
        Join-Path $repoRoot $WorkingDirectory
    }
    Invoke-Gate -Id $Id -Command $commandText -Class $Class -Action {
        Push-Location -LiteralPath $workingDirectoryPath
        try {
            & cargo @Arguments
        } finally {
            Pop-Location
        }
    }
}

function Find-MsvcLinker {
    $linker = Get-Command link.exe -ErrorAction SilentlyContinue
    if ($linker) {
        return $linker
    }

    $installer = if (${env:ProgramFiles(x86)}) {
        Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    } else {
        $null
    }
    $installations = @()
    if ($installer -and (Test-Path -LiteralPath $installer)) {
        $installations += @(& $installer -products * -property installationPath 2>$null)
    }
    $installations += @(
        "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools",
        "C:\Program Files\Microsoft Visual Studio\18\BuildTools"
    )

    foreach ($installation in ($installations | Where-Object { $_ } | Select-Object -Unique)) {
        $msvcRoot = Join-Path ([string]$installation) "VC\Tools\MSVC"
        if (-not (Test-Path -LiteralPath $msvcRoot)) {
            continue
        }
        foreach ($toolset in (Get-ChildItem -LiteralPath $msvcRoot -Directory -ErrorAction SilentlyContinue)) {
            foreach ($candidate in @(
                (Join-Path $toolset.FullName "bin\Hostx64\x64\link.exe"),
                (Join-Path $toolset.FullName "bin\Hostx86\x64\link.exe")
            )) {
                if (Test-Path -LiteralPath $candidate) {
                    return Get-Item -LiteralPath $candidate
                }
            }
        }
    }
    return $null
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
    $isWindowsHost = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
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

    if ($isWindowsHost) {
        $msvcTarget = "x86_64-pc-windows-msvc"
        $msvcLinker = Find-MsvcLinker
        if ($SkipBuild) {
            Add-SyntheticResult -Id "windows-msvc-check" -Status "SKIP" -Class "host" `
                -Command "cargo build --workspace --all-targets --target $msvcTarget" `
                -Detail "explicitly skipped"
            Add-SyntheticResult -Id "windows-msvc-release-build" -Status "SKIP" -Class "host" `
                -Command "cargo build --workspace --release --target $msvcTarget" `
                -Detail "explicitly skipped"
        } elseif ($null -eq $msvcLinker) {
            Add-SyntheticResult -Id "windows-msvc-check" -Status "SKIP" -Class "host" `
                -Command "cargo build --workspace --all-targets --target $msvcTarget" `
                -Detail "MSVC link.exe is unavailable"
            Add-SyntheticResult -Id "windows-msvc-release-build" -Status "SKIP" -Class "host" `
                -Command "cargo build --workspace --release --target $msvcTarget" `
                -Detail "MSVC link.exe is unavailable"
        } else {
            Invoke-CargoGate -Id "windows-msvc-check" `
                -Arguments (@("build", "--workspace", "--all-targets", "--target", $msvcTarget) + $cargoFlags) `
                -Class "host"
            Invoke-CargoGate -Id "windows-msvc-release-build" `
                -Arguments (@("build", "--workspace", "--release", "--target", $msvcTarget) + $cargoFlags) `
                -Class "host"
        }
    }

    if ($SkipPackaging) {
        Add-SyntheticResult -Id "package-release" -Status "SKIP" -Class "required" `
            -Command "python scripts/package_release.py --binary target/release/shph(.exe)" `
            -Detail "explicitly skipped"
    } elseif ($null -eq (Get-Command python -ErrorAction SilentlyContinue)) {
        Add-SyntheticResult -Id "package-release" -Status "SKIP" -Class "required" `
            -Command "python scripts/package_release.py --binary target/release/shph(.exe)" `
            -Detail "python is not installed"
    } else {
        $releaseBinaryName = if ($isWindowsHost) { "shph.exe" } else { "shph" }
        $releaseBinary = Join-Path $repoRoot (Join-Path "target" (Join-Path "release" $releaseBinaryName))
        if (-not (Test-Path -LiteralPath $releaseBinary -PathType Leaf)) {
            Add-SyntheticResult -Id "package-release" -Status "BLOCKED" -Class "required" `
                -Command "python scripts/package_release.py --binary $releaseBinary" `
                -Detail "release binary is missing: $releaseBinary"
        } else {
            $packageOutput = Join-Path $resolvedOutput "package-$stamp"
            $packageArguments = @(
                "scripts/package_release.py",
                "--binary", $releaseBinary,
                "--output", $packageOutput
            )
            if ($AllowDirty) {
                $packageArguments += "--allow-dirty"
            }
            Invoke-Gate -Id "package-release" `
                -Command ("python " + (Join-CommandArguments -Arguments $packageArguments)) `
                -Action {
                & python @packageArguments
            }
        }
    }

    Invoke-CargoGate -Id "benchmark-check" `
        -Arguments (@("check", "--all-targets") + $cargoFlags) `
        -WorkingDirectory "benchmarks"
    Invoke-Gate -Id "benchmark-fmt" `
        -Command "cargo fmt --manifest-path benchmarks/Cargo.toml -- --check" -Action {
        & cargo fmt --manifest-path (Join-Path $repoRoot "benchmarks\Cargo.toml") -- --check
    }
    Invoke-CargoGate -Id "benchmark-clippy" `
        -Arguments (@("clippy", "--all-targets") + $cargoFlags + @("--", "-D", "warnings")) `
        -WorkingDirectory "benchmarks"
    if ($SkipTests) {
        Add-SyntheticResult -Id "benchmark-tests" -Status "SKIP" -Class "required" `
            -Command "pushd benchmarks; cargo test --all-targets" -Detail "explicitly skipped"
    } else {
        Invoke-CargoGate -Id "benchmark-tests" `
            -Arguments (@("test", "--all-targets") + $cargoFlags) `
            -WorkingDirectory "benchmarks"
    }
    if ($SkipBuild) {
        Add-SyntheticResult -Id "benchmark-release-build" -Status "SKIP" -Class "required" `
            -Command "pushd benchmarks; cargo build --release" -Detail "explicitly skipped"
    } else {
        Invoke-CargoGate -Id "benchmark-release-build" `
            -Arguments (@("build", "--release") + $cargoFlags) `
            -WorkingDirectory "benchmarks"
    }
    if ($isWindowsHost) {
        $benchmarkMsvcTarget = "x86_64-pc-windows-msvc"
        $benchmarkMsvcLinker = Find-MsvcLinker
        if ($SkipBuild) {
            Add-SyntheticResult -Id "windows-msvc-benchmark-release-build" -Status "SKIP" -Class "host" `
                -Command "pushd benchmarks; cargo build --release --target $benchmarkMsvcTarget" `
                -Detail "explicitly skipped"
        } elseif ($null -eq $benchmarkMsvcLinker) {
            Add-SyntheticResult -Id "windows-msvc-benchmark-release-build" -Status "SKIP" -Class "host" `
                -Command "pushd benchmarks; cargo build --release --target $benchmarkMsvcTarget" `
                -Detail "MSVC link.exe is unavailable"
        } else {
            Invoke-CargoGate -Id "windows-msvc-benchmark-release-build" `
                -Arguments (@("build", "--release", "--target", $benchmarkMsvcTarget) + $cargoFlags) `
                -Class "host" `
                -WorkingDirectory "benchmarks"
        }
    }

    if ($SkipBenchmarks) {
        Add-SyntheticResult -Id "benchmark-smoke-secure-default" -Status "SKIP" -Class "required" `
            -Command "shph-benchmarks --profile secure-default --suite all" `
            -Detail "explicitly skipped"
        Add-SyntheticResult -Id "benchmark-smoke-classical-lab" -Status "SKIP" -Class "required" `
            -Command "shph-benchmarks --profile classical-lab --suite all" `
            -Detail "explicitly skipped"
    } else {
        $benchmarkBinaryName = if ($isWindowsHost) { "shph-benchmarks.exe" } else { "shph-benchmarks" }
        $benchmarkCandidates = if ($isWindowsHost) {
            @(
                (Join-Path $repoRoot (Join-Path "benchmarks" (Join-Path "target" (Join-Path "x86_64-pc-windows-msvc" (Join-Path "release" $benchmarkBinaryName))))),
                (Join-Path $repoRoot (Join-Path "benchmarks" (Join-Path "target" (Join-Path "release" $benchmarkBinaryName))))
            )
        } else {
            @(
                (Join-Path $repoRoot (Join-Path "benchmarks" (Join-Path "target" (Join-Path "release" $benchmarkBinaryName))))
            )
        }
        $benchmarkBinary = $benchmarkCandidates | Where-Object {
            Test-Path -LiteralPath $_ -PathType Leaf
        } | Select-Object -First 1
        if ($null -eq $benchmarkBinary -or -not (Test-Path -LiteralPath $benchmarkBinary -PathType Leaf)) {
            Add-SyntheticResult -Id "benchmark-smoke-secure-default" -Status "FAIL" -Class "required" `
                -Command "shph-benchmarks --profile secure-default --suite all" `
                -Detail "benchmark executable is missing; checked: $($benchmarkCandidates -join ', ')"
            Add-SyntheticResult -Id "benchmark-smoke-classical-lab" -Status "BLOCKED" -Class "required" `
                -Command "shph-benchmarks --profile classical-lab --suite all" `
                -Detail "blocked because benchmark executable is missing"
        } else {
            foreach ($benchmarkProfile in @("secure-default", "classical-lab")) {
                $benchmarkId = "benchmark-smoke-$($benchmarkProfile -replace '-', '-')"
                Invoke-Gate -Id $benchmarkId `
                    -Command "$benchmarkBinary --profile $benchmarkProfile --suite all --iterations $BenchmarkIterations --frames $BenchmarkFrames" `
                    -Action {
                    & $benchmarkBinary `
                        --profile $benchmarkProfile `
                        --suite all `
                        --iterations $BenchmarkIterations `
                        --frames $BenchmarkFrames
                }
            }
        }
    }

    Invoke-CargoGate -Id "fuzz-check" `
        -Arguments (@("check", "--all-targets") + $cargoFlags) `
        -WorkingDirectory "fuzz"
    Invoke-CargoGate -Id "fuzz-clippy" `
        -Arguments (@("clippy", "--all-targets") + $cargoFlags + @("--", "-D", "warnings")) `
        -WorkingDirectory "fuzz"
    Invoke-Gate -Id "fuzz-fmt" `
        -Command "cargo fmt --manifest-path fuzz/Cargo.toml -- --check" -Action {
        & cargo fmt --manifest-path (Join-Path $repoRoot "fuzz\Cargo.toml") -- --check
    }
    if ($SkipFuzzSmoke) {
        Add-SyntheticResult -Id "fuzz-smoke" -Status "SKIP" -Class "required" `
            -Command "cargo +$FuzzToolchain fuzz run <target> -- -runs=$FuzzRuns" `
            -Detail "explicitly skipped"
    } elseif ($null -eq (Get-Command cargo-fuzz -ErrorAction SilentlyContinue)) {
        Add-SyntheticResult -Id "fuzz-smoke" -Status "SKIP" -Class "required" `
            -Command "cargo +$FuzzToolchain fuzz run <target> -- -runs=$FuzzRuns" `
            -Detail "cargo-fuzz is not installed"
    } else {
        $installedToolchains = @(& rustup toolchain list 2>&1 | ForEach-Object { $_.ToString() })
        if (-not ($installedToolchains -match [regex]::Escape($FuzzToolchain))) {
            Add-SyntheticResult -Id "fuzz-smoke" -Status "SKIP" -Class "required" `
                -Command "rustup toolchain list" `
                -Detail "$FuzzToolchain is not installed"
        } else {
            $fuzzTargets = @(
                "frame_decode",
                "config_parse",
                "audit_record",
                "replay_window",
                "shroud2_datagram",
                "phantom_one_envelope"
            )
            foreach ($fuzzTarget in $fuzzTargets) {
                Invoke-Gate -Id "fuzz-smoke-$fuzzTarget" `
                    -Command "cargo +$FuzzToolchain fuzz run $fuzzTarget -- -runs=$FuzzRuns" -Action {
                    Push-Location -LiteralPath (Join-Path $repoRoot "fuzz")
                    try {
                        & cargo "+$FuzzToolchain" fuzz run $fuzzTarget -- "-runs=$FuzzRuns"
                    } finally {
                        Pop-Location
                    }
                }
            }
        }
    }
    if (Test-Path -LiteralPath (Join-Path $repoRoot "shph-edge/Cargo.toml")) {
        Invoke-Gate -Id "edge-fmt" `
            -Command "cargo fmt --manifest-path shph-edge/Cargo.toml -- --check" -Action {
            & cargo fmt --manifest-path (Join-Path $repoRoot "shph-edge\Cargo.toml") -- --check
        }
        Invoke-CargoGate -Id "edge-check" `
            -Arguments (@("check", "--all-targets") + $cargoFlags) `
            -WorkingDirectory "shph-edge"
        if ($SkipTests) {
            Add-SyntheticResult -Id "edge-tests" -Status "SKIP" -Class "required" `
                -Command "pushd shph-edge; cargo test --all-targets" -Detail "explicitly skipped"
        } else {
            Invoke-CargoGate -Id "edge-tests" `
                -Arguments (@("test", "--all-targets") + $cargoFlags) `
                -WorkingDirectory "shph-edge"
        }
        Invoke-CargoGate -Id "edge-clippy" `
            -Arguments (@("clippy", "--all-targets") + $cargoFlags + @("--", "-D", "warnings")) `
            -WorkingDirectory "shph-edge"
        if ($SkipHttp3) {
            Add-SyntheticResult -Id "edge-http3-check" -Status "SKIP" -Class "required" `
                -Command "pushd shph-edge; cargo check --features http3 --all-targets" `
                -Detail "explicitly skipped"
            Add-SyntheticResult -Id "edge-http3-tests" -Status "SKIP" -Class "required" `
                -Command "pushd shph-edge; cargo test --features http3 --all-targets" `
                -Detail "explicitly skipped"
            Add-SyntheticResult -Id "edge-http3-clippy" -Status "SKIP" -Class "required" `
                -Command "pushd shph-edge; cargo clippy --features http3 --all-targets" `
                -Detail "explicitly skipped"
        } else {
            Invoke-CargoGate -Id "edge-http3-check" `
                -Arguments (@("check", "--features", "http3", "--all-targets") + $cargoFlags) `
                -WorkingDirectory "shph-edge"
            if ($SkipTests) {
                Add-SyntheticResult -Id "edge-http3-tests" -Status "SKIP" -Class "required" `
                    -Command "pushd shph-edge; cargo test --features http3 --all-targets" `
                    -Detail "explicitly skipped"
            } else {
                Invoke-CargoGate -Id "edge-http3-tests" `
                    -Arguments (@("test", "--features", "http3", "--all-targets") + $cargoFlags) `
                    -WorkingDirectory "shph-edge"
            }
            Invoke-CargoGate -Id "edge-http3-clippy" `
                -Arguments (@("clippy", "--features", "http3", "--all-targets") + $cargoFlags + @("--", "-D", "warnings")) `
                -WorkingDirectory "shph-edge"
        }
        if ($SkipBuild) {
            Add-SyntheticResult -Id "edge-release-build" -Status "SKIP" -Class "required" `
                -Command "pushd shph-edge; cargo build --release" -Detail "explicitly skipped"
        } else {
            Invoke-CargoGate -Id "edge-release-build" `
                -Arguments (@("build", "--release") + $cargoFlags) `
                -WorkingDirectory "shph-edge"
        }
    }

    if ($SkipAudit) {
        foreach ($auditTarget in @("root", "benchmarks", "fuzz", "shph-edge")) {
            Add-SyntheticResult -Id "cargo-audit-$auditTarget" -Status "SKIP" -Class "required" `
                -Command "pushd $auditTarget; cargo audit --deny warnings" -Detail "explicitly skipped"
        }
    } elseif ($null -eq (Get-Command cargo-audit -ErrorAction SilentlyContinue)) {
        foreach ($auditTarget in @("root", "benchmarks", "fuzz", "shph-edge")) {
            Add-SyntheticResult -Id "cargo-audit-$auditTarget" -Status "SKIP" -Class "required" `
                -Command "pushd $auditTarget; cargo audit --deny warnings" -Detail "cargo-audit is not installed"
        }
    } else {
        $auditArguments = @("audit", "--deny", "warnings")
        if (-not $AllowNetwork) {
            $auditArguments += "--no-fetch"
        }
        Invoke-CargoGate -Id "cargo-audit-root" -Arguments $auditArguments
        foreach ($auditTarget in @("benchmarks", "fuzz", "shph-edge")) {
            Invoke-CargoGate -Id "cargo-audit-$auditTarget" `
                -Arguments $auditArguments `
                -WorkingDirectory $auditTarget
        }
    }
}

$isWindowsHost = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
if ($SkipNative) {
    Add-SyntheticResult -Id "native-host-toolchain" -Status "SKIP" -Class "host" `
        -Command "native host preflight" -Detail "explicitly skipped"
} elseif ($isWindowsHost) {
    $linker = Find-MsvcLinker
    if ($null -eq $linker) {
        Add-SyntheticResult -Id "native-host-toolchain" -Status "SKIP" -Class "host" `
            -Command "Get-Command link.exe" -Detail "MSVC link.exe is unavailable"
    } else {
        Add-SyntheticResult -Id "native-host-toolchain" -Status "PASS" -Class "host" `
            -Command "Get-Command link.exe" -Detail $linker.FullName
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
