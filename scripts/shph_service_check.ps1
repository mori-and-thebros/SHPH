[CmdletBinding()]
param(
    [string]$Config = "C:\ProgramData\SHPH\host.toml",
    [string]$Binary = "C:\Program Files\SHPH\shph.exe",
    [string]$Service = "SHPH",
    [string]$Listen = "127.0.0.1:443",
    [string]$Output,
    [switch]$AllowRemoteProbe
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Get-Command python.exe -ErrorAction SilentlyContinue
if ($null -eq $python) {
    $python = Get-Command python3.exe -ErrorAction SilentlyContinue
}
if ($null -eq $python) {
    throw "Python 3 is required to run the bounded SHPH operations collector."
}

$arguments = @(
    (Join-Path $scriptRoot "shph_ops_check.py"),
    "--binary", $Binary,
    "--config", $Config,
    "--unit", $Service,
    "--listen", $Listen,
    "--strict"
)
if ($Output) {
    $arguments += @("--output", $Output)
}
if ($AllowRemoteProbe) {
    $arguments += "--allow-remote-probe"
}

& $python.Source @arguments
exit $LASTEXITCODE
