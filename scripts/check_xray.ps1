[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $env:LOCALAPPDATA 'Xray\config.json'),
    [string]$XrayPath = (Join-Path $env:LOCALAPPDATA 'Xray\xray.exe'),
    [string]$SocksHost = '127.0.0.1',
    [int]$SocksPort = 10808
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Fail([string]$Message) {
    Write-Error $Message
    exit 1
}

Write-Host "SHPH Xray underlay check"

if (-not (Test-Path -LiteralPath $XrayPath -PathType Leaf)) {
    Fail "Xray executable not found: $XrayPath"
}
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    Fail "Xray configuration not found: $ConfigPath"
}

try {
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
} catch {
    Fail "Xray configuration is not valid JSON: $($_.Exception.Message)"
}

$socks = @($config.inbounds | Where-Object { $_.protocol -eq 'socks' })
if ($socks.Count -eq 0) {
    Fail "No SOCKS inbound was found in the Xray configuration"
}

$matchingSocks = @(
    $socks | Where-Object {
        ([string]$_.listen -eq $SocksHost) -and ([int]$_.port -eq $SocksPort)
    }
)
if ($matchingSocks.Count -eq 0) {
    Fail "No SOCKS inbound is configured on $SocksHost`:$SocksPort"
}

$hasVless = @(
    @($config.inbounds) + @($config.outbounds) |
        Where-Object { $_.protocol -eq 'vless' }
).Count -gt 0
if (-not $hasVless) {
    Write-Warning "No VLESS inbound or outbound found; the SOCKS listener may not reach SHPH"
}

$testOutput = & $XrayPath run -test -config $ConfigPath 2>&1
if ($LASTEXITCODE -ne 0) {
    Fail ("Xray configuration test failed:`n" + ($testOutput -join [Environment]::NewLine))
}
Write-Host "[PASS] Xray configuration test"

$connection = [Net.Sockets.TcpClient]::new()
try {
    $connection.Connect($SocksHost, $SocksPort)
    $stream = $connection.GetStream()
    $request = [byte[]](0x05, 0x01, 0x00)
    $stream.Write($request, 0, $request.Length)
    $response = [byte[]]::new(2)
    $read = $stream.Read($response, 0, $response.Length)
    if ($read -ne 2 -or $response[0] -ne 0x05 -or $response[1] -ne 0x00) {
        Fail "SOCKS5 listener did not accept the unauthenticated method"
    }
} catch {
    Fail "SOCKS5 listener check failed on $SocksHost`:$SocksPort : $($_.Exception.Message)"
} finally {
    if ($null -ne $connection) {
        $connection.Dispose()
    }
}

Write-Host "[PASS] SOCKS5 listener responds on $SocksHost`:$SocksPort"
Write-Host "Result: Xray is ready to carry an SHPH TCP underlay"
