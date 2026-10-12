[CmdletBinding()]
param(
    [ValidateRange(1, 86400)]
    [int]$MaxTotalTimeSeconds = 21600,
    [string]$OutputDirectory = ".\benchmark-runs\fuzz-campaign-concurrent",
    [string]$NightlyToolchain = "nightly-2026-07-16",
    [string]$AsanRuntimeDirectory = ""
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
    [System.IO.Path]::GetFullPath($OutputDirectory)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDirectory))
}
$campaignName = Split-Path -Leaf $resolvedOutput
if ([string]::IsNullOrWhiteSpace($campaignName)) {
    throw "OutputDirectory must name a campaign directory"
}
$artifactRoot = Join-Path $fuzzRoot "artifacts\$campaignName"

if (Test-Path -LiteralPath $resolvedOutput) {
    throw "Output already exists: $resolvedOutput"
}
if (Test-Path -LiteralPath $artifactRoot) {
    throw "Artifact output already exists: $artifactRoot"
}

if ([string]::IsNullOrWhiteSpace($AsanRuntimeDirectory)) {
    $visualStudioRoots = @(
        if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
            Join-Path $env:ProgramFiles "Microsoft Visual Studio"
        }
        if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
            Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio"
        }
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }

    foreach ($visualStudioRoot in $visualStudioRoots) {
        $asan = Get-ChildItem `
            -LiteralPath $visualStudioRoot `
            -Recurse `
            -Filter "clang_rt.asan_dynamic-x86_64.dll" `
            -File `
            -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -ne $asan) {
            $AsanRuntimeDirectory = $asan.DirectoryName
            break
        }
    }
}

if ([string]::IsNullOrWhiteSpace($AsanRuntimeDirectory)) {
    throw "MSVC AddressSanitizer runtime directory was not found"
}
$asanDll = Join-Path $AsanRuntimeDirectory "clang_rt.asan_dynamic-x86_64.dll"
if (-not (Test-Path -LiteralPath $asanDll -PathType Leaf)) {
    throw "ASan runtime is missing: $asanDll"
}

$rustup = Get-Command rustup.exe -ErrorAction Stop
$cargo = Get-Command cargo.exe -ErrorAction Stop
$cargoFuzz = Get-Command cargo-fuzz.exe -ErrorAction Stop

$toolchains = @(
    & $rustup.Source toolchain list 2>&1 |
        ForEach-Object { $_.ToString() }
)
if ($LASTEXITCODE -ne 0) {
    throw "rustup toolchain list failed with exit code $LASTEXITCODE"
}
if (-not ($toolchains -match [regex]::Escape($NightlyToolchain))) {
    throw "required toolchain is not installed: $NightlyToolchain"
}

$rustcVersion = @(
    & $rustup.Source run $NightlyToolchain rustc -V 2>&1 |
        ForEach-Object { $_.ToString() }
) -join " "
$rustcExitCode = $LASTEXITCODE
if ($rustcExitCode -ne 0) {
    throw "unable to query $NightlyToolchain rustc version (exit code $rustcExitCode)"
}

$cargoFuzzVersion = @(
    & $cargoFuzz.Source --version 2>&1 |
        ForEach-Object { $_.ToString() }
) -join " "
$cargoFuzzExitCode = $LASTEXITCODE
if ($cargoFuzzExitCode -ne 0) {
    throw "unable to query cargo-fuzz version (exit code $cargoFuzzExitCode)"
}

New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null
New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
$env:PATH = "$AsanRuntimeDirectory;$env:PATH"

$revision = @(
    & git -C $repoRoot rev-parse HEAD 2>$null |
        ForEach-Object { $_.ToString() }
) -join ""
$treeState = @(
    & git -C $repoRoot status --porcelain=v1 2>$null |
        ForEach-Object { $_.ToString() }
) -join "`n"
$treeDirty = if ([string]::IsNullOrWhiteSpace($treeState)) {
    "false"
} else {
    "true"
}
$startedUtc = (Get-Date).ToUniversalTime().ToString("o")

@(
    "campaign=$campaignName"
    "started_utc=$startedUtc"
    "revision=$revision"
    "tree_dirty=$treeDirty"
    "nightly=$NightlyToolchain"
    "rustc=$rustcVersion"
    "cargo_fuzz=$cargoFuzzVersion"
    "asan_runtime=$AsanRuntimeDirectory"
    "max_total_time_seconds=$MaxTotalTimeSeconds"
    "target_count=$($targets.Count)"
    "execution_model=all_targets_concurrent"
    "status_policy=PASS requires process exit code 0 and a libFuzzer completion marker"
) | Set-Content -LiteralPath (Join-Path $resolvedOutput "campaign-info.txt") -Encoding utf8

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value -match '[\s"]') {
        return '"' + $Value.Replace('"', '\"') + '"'
    }
    return $Value
}

function Update-Record {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [switch]$WaitForExit
    )

    try {
        $Record.Process.Refresh()
        $hasExited = $Record.Process.HasExited
        if (-not $hasExited) {
            if (-not $WaitForExit) {
                return
            }
            [void]$Record.Process.WaitForExit()
        }

        # WaitForExit also flushes redirected stdout/stderr before log parsing.
        [void]$Record.Process.WaitForExit()
        $Record.Process.Refresh()
    } catch {
        $Record.Status = "UNKNOWN"
        $Record.Reason = "process handle could not be completed: $($_.Exception.Message)"
        return
    }

    try {
        $Record.ExitCode = [int]$Record.Process.ExitCode
    } catch {
        $Record.ExitCode = $null
    }

    $logParts = New-Object System.Collections.Generic.List[string]
    foreach ($path in @($Record.Stdout, $Record.Stderr)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $logParts.Add((Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue))
        }
    }
    $logText = $logParts -join "`n"

    $Record.CompletionMarker = [regex]::IsMatch(
        $logText,
        '(?m)^\s*(?:Done\s+\d+\s+runs\s+in\s+\d+\s+second|#\d+\s+DONE\s+)'
    )
    $Record.FatalMarker = [regex]::IsMatch(
        $logText,
        '(?im)^\s*(?:Error:\s+Fuzz target exited|thread .* panicked at|==\d+==ERROR:)|AddressSanitizer:|LeakSanitizer:|UndefinedBehaviorSanitizer:|STATUS_[A-Z_]+'
    )
    $Record.ArtifactCount = @(
        Get-ChildItem -LiteralPath $Record.ArtifactDirectory -File -ErrorAction SilentlyContinue
    ).Count

    if ($Record.FatalMarker) {
        $Record.Status = "FAIL"
        $Record.Reason = "fatal log marker"
    } elseif ($null -ne $Record.ExitCode) {
        if ($Record.ExitCode -eq 0 -and $Record.CompletionMarker) {
            $Record.Status = "PASS"
            $Record.Reason = "process exit 0 and completion marker present"
        } elseif ($Record.ExitCode -eq 0) {
            $Record.Status = "FAIL"
            $Record.Reason = "process exit 0 but completion marker missing"
        } else {
            $Record.Status = "FAIL"
            $Record.Reason = "process exit code $($Record.ExitCode)"
        }
    } elseif ($Record.CompletionMarker) {
        # Keep this distinct from PASS: it is useful diagnostic evidence but
        # does not certify the process exit status.
        $Record.Status = "PASS_LOGGED"
        $Record.Reason = "completion marker present but process exit code unavailable"
    } else {
        $Record.Status = "UNKNOWN"
        $Record.Reason = "neither a completion marker nor an exit code was captured"
    }
}

function Write-State {
    $lines = @("target,pid,status,exit_code,elapsed_seconds,completion_marker,artifact_count,stdout,stderr")
    foreach ($record in $records) {
        $elapsed = ((Get-Date) - $record.Started).TotalSeconds.ToString(
            "0.000",
            [Globalization.CultureInfo]::InvariantCulture
        )
        $exitCode = if ($null -eq $record.ExitCode) {
            "UNKNOWN"
        } else {
            [string]$record.ExitCode
        }
        $completion = if ($record.CompletionMarker) { "true" } else { "false" }
        $lines += ("{0},{1},{2},{3},{4},{5},{6},{7},{8}" -f `
            $record.Target,
            $record.Process.Id,
            $record.Status,
            $exitCode,
            $elapsed,
            $completion,
            $record.ArtifactCount,
            [IO.Path]::GetFileName($record.Stdout),
            [IO.Path]::GetFileName($record.Stderr))
    }
    $lines | Set-Content -LiteralPath (Join-Path $resolvedOutput "campaign-state.csv") -Encoding utf8
}

$records = New-Object System.Collections.Generic.List[object]
foreach ($target in $targets) {
    $targetArtifact = Join-Path $artifactRoot $target
    New-Item -ItemType Directory -Path $targetArtifact -Force | Out-Null
    $stdout = Join-Path $resolvedOutput "$target.stdout.log"
    $stderr = Join-Path $resolvedOutput "$target.stderr.log"
    $artifactPrefix = ($targetArtifact.Replace("\", "/") + "/")
    $arguments = @(
        "+$NightlyToolchain",
        "fuzz",
        "run",
        $target,
        "--",
        "-max_total_time=$MaxTotalTimeSeconds",
        "-print_final_stats=1",
        "-artifact_prefix=$artifactPrefix"
    )
    if ($target -eq "frame_decode") {
        $arguments += "-dict=shroud.dict"
    }
    $argumentString = (($arguments | ForEach-Object {
        Quote-ProcessArgument -Value $_
    }) -join " ")
    $started = Get-Date
    $process = Start-Process `
        -FilePath $cargo.Source `
        -ArgumentList $argumentString `
        -WorkingDirectory $fuzzRoot `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru `
        -WindowStyle Hidden
    $records.Add([pscustomobject]@{
        Target = $target
        Process = $process
        Started = $started
        Stdout = $stdout
        Stderr = $stderr
        ArtifactDirectory = $targetArtifact
        ExitCode = $null
        Status = "RUNNING"
        CompletionMarker = $false
        FatalMarker = $false
        ArtifactCount = 0
        Reason = ""
    })
    Write-Host ("started target={0} pid={1} at={2}" -f `
        $target,
        $process.Id,
        $started.ToUniversalTime().ToString("o"))
}

Write-State
while ($true) {
    $activeCount = 0
    foreach ($record in $records) {
        Update-Record -Record $record
        if ($record.Status -eq "RUNNING") {
            $activeCount++
        }
    }
    Write-State
    if ($activeCount -eq 0) {
        break
    }
    Write-Host (
        (Get-Date).ToUniversalTime().ToString("o") +
        " active_targets=" +
        $activeCount
    )
    Start-Sleep -Seconds 30
}

foreach ($record in $records) {
    Update-Record -Record $record -WaitForExit
}

$finishedUtc = (Get-Date).ToUniversalTime().ToString("o")
$summary = @("target,status,exit_code,elapsed_seconds,completion_marker,artifact_count,stdout,stderr")
$failures = 0
foreach ($record in $records) {
    $elapsed = ((Get-Date) - $record.Started).TotalSeconds.ToString(
        "0.000",
        [Globalization.CultureInfo]::InvariantCulture
    )
    $exitCode = if ($null -eq $record.ExitCode) {
        "UNKNOWN"
    } else {
        [string]$record.ExitCode
    }
    $completion = if ($record.CompletionMarker) { "true" } else { "false" }
    $summary += ("{0},{1},{2},{3},{4},{5},{6},{7}" -f `
        $record.Target,
        $record.Status,
        $exitCode,
        $elapsed,
        $completion,
        $record.ArtifactCount,
        [IO.Path]::GetFileName($record.Stdout),
        [IO.Path]::GetFileName($record.Stderr))
    if ($record.Status -ne "PASS") {
        $failures++
    }
}

$summary | Set-Content -LiteralPath (Join-Path $resolvedOutput "summary.csv") -Encoding utf8
Add-Content -LiteralPath (Join-Path $resolvedOutput "campaign-info.txt") `
    -Value @(
        "finished_utc=$finishedUtc"
        "result_status=$(if ($failures -eq 0) { 'PASS' } else { 'FAIL' })"
        "failure_count=$failures"
    )
Write-State
Write-Host ("campaign finished; summary=" + (Join-Path $resolvedOutput "summary.csv"))

if ($failures -ne 0) {
    exit 1
}
