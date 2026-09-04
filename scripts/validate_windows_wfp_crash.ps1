#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Exercises persistent Windows WFP killswitch state across hard termination.

.DESCRIPTION
    This is a single-host, elevated Windows test. It creates two fresh local
    identities, starts a no-TUN TCP listener, starts a native Wintun client
    with --killswitch, hard-terminates the client, and verifies that the
    SHPH-owned persistent WFP filters are still present. It then runs an
    explicit `shph down`, verifies that the filters are gone, and checks for
    temporary adapter/control-plane residue.

    The test intentionally does not claim Windows-to-Windows forwarding,
    Internet reachability, or crash-time packet-leak prevention beyond the
    observable WFP policy persistence and cleanup sequence.
#>

[CmdletBinding()]
param(
    [string]$Binary = ".\target\release\shph.exe",
    [string]$Wintun = ".\wintun.dll",
    [string]$OutputDirectory = "",
    [ValidateRange(1024, 65535)]
    [int]$Port = 52841,
    [switch]$KeepTemporary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = [System.IO.Path]::GetFullPath($PSScriptRoot + "\..")
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot "benchmark-runs\windows-wfp-crash-$stamp"
} elseif (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot $OutputDirectory
}
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
$repoPrefix = $repoRoot.TrimEnd("\") + "\"
if (-not $resolvedOutput.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputDirectory must remain inside the repository: $resolvedOutput"
}
if (Test-Path -LiteralPath $resolvedOutput) {
    throw "OutputDirectory already exists; choose a fresh path: $resolvedOutput"
}
New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null

function Resolve-RepoPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) {
        $Path
    } else {
        Join-Path $repoRoot $Path
    }
    return [System.IO.Path]::GetFullPath($candidate)
}

$resolvedBinary = Resolve-RepoPath -Path $Binary
$resolvedWintun = Resolve-RepoPath -Path $Wintun
if (-not (Test-Path -LiteralPath $resolvedBinary -PathType Leaf)) {
    throw "Release CLI not found: $resolvedBinary"
}
if (-not (Test-Path -LiteralPath $resolvedWintun -PathType Leaf)) {
    throw "Wintun runtime not found: $resolvedWintun"
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Administrator elevation is required."
}

$signature = Get-AuthenticodeSignature -LiteralPath $resolvedWintun
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "Wintun Authenticode status is $($signature.Status), not Valid."
}
$wintunHash = (Get-FileHash -LiteralPath $resolvedWintun -Algorithm SHA256).Hash.ToUpperInvariant()
if ($wintunHash -notmatch "^[0-9A-F]{64}$") {
    throw "Unable to derive a valid Wintun SHA-256 digest."
}

$releaseDirectory = Split-Path -Parent $resolvedBinary
$deployedWintun = Join-Path $releaseDirectory "wintun.dll"
Copy-Item -LiteralPath $resolvedWintun -Destination $deployedWintun -Force
$deployedHash = (Get-FileHash -LiteralPath $deployedWintun -Algorithm SHA256).Hash.ToUpperInvariant()
if ($deployedHash -cne $wintunHash) {
    throw "Application-local wintun.dll hash differs from the source runtime."
}

$env:SHPH_TUN_NATIVE = "1"
$env:SHPH_WINTUN_SHA256 = $wintunHash

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    ("shph-wfp-crash-" + [Guid]::NewGuid().ToString("N"))
$serverDirectory = Join-Path $tempRoot "server"
$clientDirectory = Join-Path $tempRoot "client"
$serverConfig = Join-Path $serverDirectory "config.toml"
$clientConfig = Join-Path $clientDirectory "config.toml"
$adapterName = "shph-f-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
$statePath = $clientConfig + ".control-plane.json"

$serverProcess = $null
$clientProcess = $null
$cleanupDone = $false
$hardKillPid = $null
$hardKillExitCode = $null
$wfpInitialCount = $null
$wfpBeforeKillCount = $null
$wfpAfterKillCount = $null
$wfpAfterCleanupCount = $null
$failureMessage = $null
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$runLogPath = Join-Path $resolvedOutput "run.log"

function Write-RunLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Line
    )

    [System.IO.File]::AppendAllText($runLogPath, $Line + [Environment]::NewLine, $utf8NoBom)
    Write-Host $Line
}

function Invoke-ShphChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    Write-RunLog (">> shph " + ($ArgumentList -join " "))
    $lines = @(& $resolvedBinary @ArgumentList 2>&1)
    $exitCode = [int]$LASTEXITCODE
    foreach ($line in $lines) {
        Write-RunLog ("   " + $line.ToString())
    }
    if ($exitCode -ne 0) {
        throw "shph command failed with exit code ${exitCode}: $($ArgumentList -join ' ')"
    }
    return ($lines -join "`n")
}

function Get-ShphValue {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    $value = Invoke-ShphChecked -ArgumentList $ArgumentList
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "shph returned an empty value: $($ArgumentList -join ' ')"
    }
    return $value.Trim()
}

function Append-Utf8 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    [System.IO.File]::AppendAllText($Path, $Text, $utf8NoBom)
}

function Set-InterfaceName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$InterfaceName
    )

    $text = [System.IO.File]::ReadAllText($Path)
    $updated = $text.Replace(
        'interface_name = "shph0"',
        ('interface_name = "' + $InterfaceName + '"')
    )
    if ($updated -eq $text) {
        throw "unable to set the generated interface name in $Path"
    }
    [System.IO.File]::WriteAllText($Path, $updated, $utf8NoBom)
}

function Read-ProcessLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ""
    }
    try {
        return [System.IO.File]::ReadAllText($Path)
    } catch {
        return ""
    }
}

function Wait-ForMarker {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Marker,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Read-ProcessLog -Path $Path).Contains($Marker)) {
            return
        }
        if ($Process.HasExited) {
            $Process.Refresh()
            $exitCode = try {
                $Process.ExitCode
            } catch {
                "unknown"
            }
            throw "process $($Process.Id) exited before marker '$Marker' (code $exitCode)"
        }
        Start-Sleep -Milliseconds 100
    }
    throw "timed out waiting for marker '$Marker' in $Path"
}

function Wait-ForTcpListener {
    param(
        [Parameter(Mandatory = $true)]
        [int]$LocalPort,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $listener = @(
            Get-NetTCPConnection -State Listen -LocalPort $LocalPort -ErrorAction SilentlyContinue
        )
        if ($listener.Count -gt 0) {
            return
        }
        if ($Process.HasExited) {
            $Process.Refresh()
            $exitCode = try {
                $Process.ExitCode
            } catch {
                "unknown"
            }
            throw "listener process $($Process.Id) exited before opening TCP port $LocalPort (code $exitCode)"
        }
        Start-Sleep -Milliseconds 100
    }
    throw "timed out waiting for a TCP listener on 127.0.0.1:$LocalPort"
}

function Wait-ForNativeClient {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process,

        [Parameter(Mandatory = $true)]
        [int]$RemotePort,

        [Parameter(Mandatory = $true)]
        [string]$InterfaceName,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $adapter = @(
            Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq $InterfaceName }
        )
        $connection = @(
            Get-NetTCPConnection -State Established -RemoteAddress "127.0.0.1" `
                -RemotePort $RemotePort -ErrorAction SilentlyContinue
        )
        if ($adapter.Count -gt 0 -and $connection.Count -gt 0) {
            return
        }
        if ($Process.HasExited) {
            $Process.Refresh()
            $exitCode = try {
                $Process.ExitCode
            } catch {
                "unknown"
            }
            throw "client process $($Process.Id) exited before native readiness (code $exitCode)"
        }
        Start-Sleep -Milliseconds 100
    }
    throw "timed out waiting for native adapter '$InterfaceName' and TCP connection to 127.0.0.1:$RemotePort"
}

function Capture-Wfp {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string]$ExtraArgument = ""
    )

    $path = Join-Path $resolvedOutput $Name
    $arguments = @("wfp", "show", "filters", "file=-", "verbose=ON")
    if (-not [string]::IsNullOrWhiteSpace($ExtraArgument)) {
        $arguments += $ExtraArgument
    }
    $lines = @(& netsh @arguments 2>&1)
    $exitCode = [int]$LASTEXITCODE
    $text = $lines -join "`n"
    [System.IO.File]::WriteAllText($path, $text + "`n", $utf8NoBom)
    if ($exitCode -ne 0) {
        throw "netsh WFP filter inspection failed with exit code $exitCode"
    }
    return $text
}

function Count-ShphFilters {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    return ([regex]::Matches($Text, "SHPH killswitch", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
}

function Write-NetworkSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $adapter = @(
        Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $adapterName } |
            Select-Object Name, InterfaceDescription, Status, ifIndex, MacAddress
    )
    $routes = @(
        Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DestinationPrefix -eq "198.18.0.0/15" -or
                $_.InterfaceAlias -eq $adapterName
            } |
            Select-Object DestinationPrefix, InterfaceAlias, ifIndex, NextHop, RouteMetric
    )
    $dns = @(
        Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -eq $adapterName } |
            Select-Object InterfaceAlias, ServerAddresses
    )
    $snapshot = [pscustomobject]@{
        adapter = $adapter
        routes = $routes
        dns = $dns
    }
    $path = Join-Path $resolvedOutput $Name
    [System.IO.File]::WriteAllText(
        $path,
        ($snapshot | ConvertTo-Json -Depth 6),
        $utf8NoBom
    )
}

function Stop-ProcessIfRunning {
    param(
        [System.Diagnostics.Process]$Process,

        [string]$Label
    )

    if ($null -eq $Process) {
        return
    }
    try {
        if (-not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            [void]$Process.WaitForExit(5000)
            Write-RunLog "$Label stopped with exit code $($Process.ExitCode)"
        }
    } catch {
        Write-RunLog "$Label stop warning: $($_.Exception.Message)"
    }
}

try {
    New-Item -ItemType Directory -Path $serverDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $clientDirectory -Force | Out-Null

    Write-RunLog "# SHPH elevated Windows WFP crash test"
    Write-RunLog "generated_utc=$((Get-Date).ToUniversalTime().ToString('o'))"
    Write-RunLog "user=$($identity.Name)"
    Write-RunLog "binary=$resolvedBinary"
    Write-RunLog "wintun=$resolvedWintun"
    Write-RunLog "wintun_signature=$($signature.Status)"
    Write-RunLog "wintun_sha256=$wintunHash"
    Write-RunLog "adapter=$adapterName"
    Write-RunLog "endpoint=127.0.0.1:$Port"

    $initialWfp = Capture-Wfp -Name "wfp-initial.txt"
    $wfpInitialCount = Count-ShphFilters -Text $initialWfp
    Write-RunLog "wfp_initial_shph_filter_count=$wfpInitialCount"
    if ($wfpInitialCount -ne 0) {
        throw "pre-existing SHPH WFP filters would make this run ambiguous"
    }

    Invoke-ShphChecked -ArgumentList @("--config", $serverConfig, "init", "--new") | Out-Null
    Invoke-ShphChecked -ArgumentList @("--config", $clientConfig, "init", "--new") | Out-Null
    Set-InterfaceName -Path $serverConfig -InterfaceName $adapterName
    Set-InterfaceName -Path $clientConfig -InterfaceName $adapterName
    $serverPublic = Get-ShphValue -ArgumentList @("--config", $serverConfig, "show-public-key")
    $serverSigning = Get-ShphValue -ArgumentList @("--config", $serverConfig, "show-signing-public-key")
    $clientPublic = Get-ShphValue -ArgumentList @("--config", $clientConfig, "show-public-key")
    $clientSigning = Get-ShphValue -ArgumentList @("--config", $clientConfig, "show-signing-public-key")

    Invoke-ShphChecked -ArgumentList @(
        "--config", $serverConfig, "add-peer", "client", "127.0.0.1",
        ([string]$Port), $clientPublic, "--sign-pubkey", $clientSigning
    ) | Out-Null
    Invoke-ShphChecked -ArgumentList @(
        "--config", $clientConfig, "add-peer", "server", "127.0.0.1",
        ([string]$Port), $serverPublic, "--sign-pubkey", $serverSigning
    ) | Out-Null

    Append-Utf8 -Path $serverConfig -Text (
        "`n[session]`nrole = `"listen`"`nbind = `"127.0.0.1:$Port`"`ntimeout_secs = 60`n"
    )
    Append-Utf8 -Path $clientConfig -Text (
        "`n[session]`nrole = `"connect`"`npeer = `"127.0.0.1:$Port`"`ntimeout_secs = 60`n"
    )
    Write-RunLog "configs_initialized_and_pinned=true"

    $listenerStdout = Join-Path $resolvedOutput "listener.stdout.log"
    $listenerStderr = Join-Path $resolvedOutput "listener.stderr.log"
    $serverProcess = Start-Process `
        -FilePath $resolvedBinary `
        -ArgumentList @("--config", $serverConfig, "up", "--no-tun", "--transport", "tcp") `
        -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $listenerStdout `
        -RedirectStandardError $listenerStderr `
        -WindowStyle Hidden `
        -PassThru
    Wait-ForTcpListener -LocalPort $Port -Process $serverProcess -TimeoutSeconds 15
    Write-RunLog "listener_pid=$($serverProcess.Id)"

    $clientStdout = Join-Path $resolvedOutput "client.stdout.log"
    $clientStderr = Join-Path $resolvedOutput "client.stderr.log"
    $clientProcess = Start-Process `
        -FilePath $resolvedBinary `
        -ArgumentList @("--config", $clientConfig, "up", "--killswitch", "--transport", "tcp") `
        -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $clientStdout `
        -RedirectStandardError $clientStderr `
        -WindowStyle Hidden `
        -PassThru
    Wait-ForNativeClient `
        -Process $clientProcess `
        -RemotePort $Port `
        -InterfaceName $adapterName `
        -TimeoutSeconds 30
    Write-RunLog "client_pid=$($clientProcess.Id)"
    Write-NetworkSnapshot -Name "network-before-kill.json"

    $beforeKillWfp = Capture-Wfp -Name "wfp-before-kill.txt"
    $wfpBeforeKillCount = Count-ShphFilters -Text $beforeKillWfp
    Write-RunLog "wfp_before_kill_shph_filter_count=$wfpBeforeKillCount"
    if ($wfpBeforeKillCount -lt 7) {
        throw "expected at least 7 SHPH WFP filters while active, found $wfpBeforeKillCount"
    }
    $hardKillPid = $clientProcess.Id
    Stop-Process -Id $hardKillPid -Force
    [void]$clientProcess.WaitForExit(5000)
    if (-not $clientProcess.HasExited) {
        throw "client process did not exit after hard termination"
    }
    $clientProcess.Refresh()
    $hardKillExitCode = try {
        $clientProcess.ExitCode
    } catch {
        $null
    }
    if ($null -eq $hardKillExitCode -or [string]::IsNullOrWhiteSpace([string]$hardKillExitCode)) {
        $hardKillExitCode = "terminated_by_Stop-Process_-Force"
    }
    Write-RunLog "hard_kill_pid=$hardKillPid"
    Write-RunLog "hard_kill_exit_code=$hardKillExitCode"
    Start-Sleep -Milliseconds 750

    $afterKillWfp = Capture-Wfp -Name "wfp-after-kill.txt"
    $wfpAfterKillCount = Count-ShphFilters -Text $afterKillWfp
    Write-RunLog "wfp_after_kill_shph_filter_count=$wfpAfterKillCount"
    if ($wfpAfterKillCount -lt 7) {
        throw "persistent WFP policy was not observable after hard termination; found $wfpAfterKillCount filters"
    }
    Write-RunLog "control_plane_state_before_cleanup=$(Test-Path -LiteralPath $statePath)"

    Invoke-ShphChecked -ArgumentList @("--config", $clientConfig, "down") | Out-Null
    $cleanupDone = $true
    Write-RunLog "explicit_down_exit=0"
    Start-Sleep -Milliseconds 250

    $afterCleanupWfp = Capture-Wfp -Name "wfp-after-cleanup.txt"
    $wfpAfterCleanupCount = Count-ShphFilters -Text $afterCleanupWfp
    Write-RunLog "wfp_after_cleanup_shph_filter_count=$wfpAfterCleanupCount"
    if ($wfpAfterCleanupCount -ne 0) {
        throw "explicit down did not remove all SHPH WFP filters; found $wfpAfterCleanupCount"
    }
    Write-NetworkSnapshot -Name "network-after-cleanup.json"

    if (Test-Path -LiteralPath $statePath) {
        throw "control-plane state residue remains: $statePath"
    }
    $adapterResidue = @(
        Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $adapterName }
    )
    if ($adapterResidue.Count -ne 0) {
        throw "temporary adapter residue remains: $adapterName"
    }

    Write-RunLog "assertions_passed=true"
}
catch {
    $failureMessage = $_.Exception.Message
    Write-RunLog "FAIL $failureMessage"
}
finally {
    if ($clientProcess -and -not $clientProcess.HasExited) {
        Stop-ProcessIfRunning -Process $clientProcess -Label "client"
    }

    if (-not $cleanupDone -and (Test-Path -LiteralPath $clientConfig -PathType Leaf)) {
        try {
            $emergencyLines = @(& $resolvedBinary "--config" $clientConfig "down" 2>&1)
            $emergencyExitCode = [int]$LASTEXITCODE
            [System.IO.File]::WriteAllText(
                (Join-Path $resolvedOutput "emergency-down.log"),
                (($emergencyLines -join "`n") + "`n"),
                $utf8NoBom
            )
            Write-RunLog "emergency_down_exit=$emergencyExitCode"
        } catch {
            Write-RunLog "emergency_down_warning=$($_.Exception.Message)"
        }
    }

    if ($serverProcess) {
        Stop-ProcessIfRunning -Process $serverProcess -Label "listener"
    }

    if (-not $KeepTemporary -and (Test-Path -LiteralPath $tempRoot)) {
        $tempFullPath = [System.IO.Path]::GetFullPath($tempRoot)
        $tempPrefix = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd("\") + "\"
        $tempLeaf = Split-Path -Leaf $tempFullPath
        if (
            $tempFullPath.StartsWith($tempPrefix, [System.StringComparison]::OrdinalIgnoreCase) -and
            $tempLeaf.StartsWith("shph-wfp-crash-", [System.StringComparison]::Ordinal)
        ) {
            Remove-Item -LiteralPath $tempFullPath -Recurse -Force
            Write-RunLog "temporary_test_directory_removed=true"
        } else {
            Write-RunLog "temporary_test_directory_cleanup_refused=$tempFullPath"
        }
    } elseif ($KeepTemporary) {
        Write-RunLog "temporary_test_directory_kept=$tempRoot"
    }
}

$result = [pscustomobject]@{
    status = if ($null -eq $failureMessage) { "PASS" } else { "FAIL" }
    generated_utc = (Get-Date).ToUniversalTime().ToString("o")
    output_directory = $resolvedOutput
    binary = $resolvedBinary
    wintun_sha256 = $wintunHash
    wintun_signature = $signature.Status.ToString()
    adapter = $adapterName
    endpoint = "127.0.0.1:$Port"
    hard_kill_pid = $hardKillPid
    hard_kill_exit_code = $hardKillExitCode
    wfp_initial_shph_filter_count = $wfpInitialCount
    wfp_before_kill_shph_filter_count = $wfpBeforeKillCount
    wfp_after_kill_shph_filter_count = $wfpAfterKillCount
    wfp_after_cleanup_shph_filter_count = $wfpAfterCleanupCount
    failure = $failureMessage
}
[System.IO.File]::WriteAllText(
    (Join-Path $resolvedOutput "result.json"),
    ($result | ConvertTo-Json -Depth 6),
    $utf8NoBom
)

$reportLines = @(
    "# Elevated Windows WFP crash-test evidence",
    "",
    "| Field | Value |",
    "| --- | --- |",
    "| Status | $($result.status) |",
    "| Generated UTC | $($result.generated_utc) |",
    "| Binary | $($result.binary) |",
    "| Wintun Authenticode | $($result.wintun_signature) |",
    "| Wintun SHA-256 | $($result.wintun_sha256) |",
    "| Native adapter | $($result.adapter) |",
    "| Local endpoint | $($result.endpoint) |",
    "| Hard-killed PID | $($result.hard_kill_pid) |",
    "| Hard-kill exit code | $($result.hard_kill_exit_code) |",
    "| WFP filters before kill | $($result.wfp_before_kill_shph_filter_count) |",
    "| WFP filters after kill | $($result.wfp_after_kill_shph_filter_count) |",
    "| WFP filters after `down` | $($result.wfp_after_cleanup_shph_filter_count) |",
    "",
    "The test used two fresh local identities and a no-TUN TCP listener.",
    "The client used native Wintun and `up --killswitch`; the client process",
    "was hard-terminated, then `shph down` was run explicitly.",
    "",
    "This is single-host WFP persistence/cleanup evidence. It does not claim",
    "Windows-to-Windows forwarding, Internet reachability, or production",
    "crash-time packet-leak prevention.",
    ""
)
if ($failureMessage) {
    $reportLines += "Failure: $failureMessage"
}
[System.IO.File]::WriteAllText(
    (Join-Path $resolvedOutput "result.md"),
    ($reportLines -join [Environment]::NewLine),
    $utf8NoBom
)

if ($failureMessage) {
    throw $failureMessage
}

Write-Host "PASS: elevated Windows WFP crash evidence captured at $resolvedOutput"
