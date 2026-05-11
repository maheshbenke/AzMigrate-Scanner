<#
.DISCLAIMER
    MIT License - Provided "AS IS", without warranty of any kind, express or implied,
    including but not limited to the warranties of merchantability, fitness for a
    particular purpose and noninfringement. In no event shall the authors or copyright
    holders be liable for any claim, damages or other liability arising from the use
    of this software. Use at your own risk. Only scan networks you are authorized to scan.

.SYNOPSIS
    Scans an IP range / CIDR (or explicit list) for servers ready for Azure Migrate Discovery.

.DESCRIPTION
    Expands one or more CIDR blocks / IP ranges into individual IPs and tests
    the TCP ports required by the Azure Migrate appliance:
      - Windows servers: WinRM (5985 HTTP / 5986 HTTPS), SMB (445), RPC (135), NetBIOS (139)
      - Linux servers:   SSH (22)
    Also performs ICMP ping and DNS lookup. Results are printed as a
    table and exported to CSV.

.PARAMETER Cidr
    One or more CIDR blocks, e.g. 10.0.0.0/24, 192.168.1.0/28.

.PARAMETER IpRange
    One or more IP ranges in "start-end" form, e.g. 10.0.0.10-10.0.0.50.

.PARAMETER ComputerName
    Explicit list of host names / IPs (alternative to CIDR/IpRange).

.PARAMETER InputFile
    File containing one entry per line. Each line may be a hostname, IP,
    CIDR block, or IP range. Lines starting with # are ignored.

.PARAMETER OsType
    Windows | Linux | Both (default: Both)

.PARAMETER OutputCsv
    Path to export results. Default: .\AzureMigrateDiscoveryScan_<timestamp>.csv

.PARAMETER TimeoutSeconds
    TCP connection timeout per port test. Default: 2

.PARAMETER ThrottleLimit
    Maximum parallel host scans (PS 7+ only). Default: 50.

.PARAMETER IncludeUnreachable
    Include hosts that did not respond to ping AND had no open ports.

.EXAMPLE
    .\Test-AzureMigrateDiscovery.ps1 -Cidr 10.0.0.0/24 -OsType Windows

.EXAMPLE
    .\Test-AzureMigrateDiscovery.ps1 -Cidr 10.0.0.0/27,10.0.1.0/28 -OsType Both

.EXAMPLE
    .\Test-AzureMigrateDiscovery.ps1 -IpRange 10.0.0.10-10.0.0.50

.EXAMPLE
    .\Test-AzureMigrateDiscovery.ps1 -InputFile .\targets.txt

.NOTES
    Reference: https://learn.microsoft.com/azure/migrate/migrate-support-matrix
#>

[CmdletBinding(DefaultParameterSetName = 'ByCidr')]
param(
    [Parameter(ParameterSetName = 'ByCidr',  Mandatory = $true)]
    [string[]]$Cidr,

    [Parameter(ParameterSetName = 'ByRange', Mandatory = $true)]
    [string[]]$IpRange,

    [Parameter(ParameterSetName = 'ByName',  Mandatory = $true)]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName = 'ByFile',  Mandatory = $true)]
    [string]$InputFile,

    [ValidateSet('Windows', 'Linux', 'Both')]
    [string]$OsType = 'Both',

    [string]$OutputCsv = ".\AzureMigrateDiscoveryScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [int]$TimeoutSeconds = 2,

    [int]$ThrottleLimit = 50,

    [switch]$IncludeUnreachable
)

# ===========================================================================
# Helper functions
# ===========================================================================

# Convert an IPv4 address object into its 32-bit numeric form so we can do
# arithmetic on it (e.g. iterate from start to end of a range).
function ConvertTo-UInt32 {
    param([System.Net.IPAddress]$Ip)
    $bytes = $Ip.GetAddressBytes()
    [Array]::Reverse($bytes)              # GetAddressBytes is big-endian; reverse for BitConverter
    return [BitConverter]::ToUInt32($bytes, 0)
}

# Reverse of the above: take a 32-bit number and format it as an IPv4 string.
function ConvertFrom-UInt32 {
    param([uint32]$Value)
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

# Expand a CIDR block (e.g. 10.0.0.0/24) into the list of usable host IPs.
# Network + broadcast addresses are skipped for /0-/30; /31 and /32 keep all IPs.
function Expand-Cidr {
    param([string]$CidrBlock)

    # Validate format: <ipv4>/<prefix>
    if ($CidrBlock -notmatch '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*/\s*(\d{1,2})\s*$') {
        Write-Warning "Invalid CIDR: $CidrBlock"; return @()
    }
    $baseIp = [System.Net.IPAddress]::Parse($Matches[1])
    $prefix = [int]$Matches[2]
    if ($prefix -lt 0 -or $prefix -gt 32) {
        Write-Warning "Invalid prefix length: $CidrBlock"; return @()
    }

    # Compute network/broadcast numerically:
    #   mask      = top <prefix> bits set
    #   network   = base AND mask
    #   broadcast = network + (2^hostBits - 1)
    $hostBits  = 32 - $prefix
    $mask      = if ($prefix -eq 0) { [uint32]0 } else { [uint32]([uint32]::MaxValue -shl $hostBits) }
    $network   = (ConvertTo-UInt32 $baseIp) -band $mask
    $broadcast = $network + [uint32]([math]::Pow(2, $hostBits) - 1)

    # For /31 (point-to-point) and /32 (single host) keep both endpoints,
    # otherwise drop network and broadcast addresses.
    if ($prefix -ge 31) { $start = $network;     $end = $broadcast }
    else                { $start = $network + 1; $end = $broadcast - 1 }

    # Materialize all IPs in the range.
    $list = New-Object System.Collections.Generic.List[string]
    for ($i = $start; $i -le $end; $i++) { $list.Add((ConvertFrom-UInt32 $i)) }
    return $list
}

# Expand an inclusive IPv4 range string "a.b.c.d-w.x.y.z" into individual IPs.
function Expand-IpRange {
    param([string]$Range)

    if ($Range -notmatch '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$') {
        Write-Warning "Invalid IP range: $Range"; return @()
    }
    $start = ConvertTo-UInt32 ([System.Net.IPAddress]::Parse($Matches[1]))
    $end   = ConvertTo-UInt32 ([System.Net.IPAddress]::Parse($Matches[2]))
    if ($end -lt $start) { Write-Warning "End IP < Start IP: $Range"; return @() }

    $list = New-Object System.Collections.Generic.List[string]
    for ($i = $start; $i -le $end; $i++) { $list.Add((ConvertFrom-UInt32 $i)) }
    return $list
}

# Classify a single input line and dispatch to the correct expander.
# Supports: blank/# comment lines, CIDR blocks, IP ranges, plain hostnames/IPs.
function Resolve-TargetEntry {
    param([string]$Entry)
    $e = $Entry.Trim()
    if (-not $e -or $e.StartsWith('#')) { return @() }                                  # skip blanks/comments
    if ($e -match '/\d{1,2}$')          { return Expand-Cidr -CidrBlock $e }            # CIDR
    if ($e -match '^\d{1,3}(\.\d{1,3}){3}\s*-\s*\d{1,3}(\.\d{1,3}){3}$') {
        return Expand-IpRange -Range $e                                                 # IP range
    }
    return ,$e                                                                          # hostname / single IP
}

# ===========================================================================
# Build target list from whichever parameter set was used
# ===========================================================================
$targets = New-Object System.Collections.Generic.List[string]

switch ($PSCmdlet.ParameterSetName) {
    'ByCidr'  { foreach ($c in $Cidr)         { Expand-Cidr     -CidrBlock $c | ForEach-Object { $targets.Add($_) } } }
    'ByRange' { foreach ($r in $IpRange)      { Expand-IpRange  -Range     $r | ForEach-Object { $targets.Add($_) } } }
    'ByName'  { foreach ($n in $ComputerName) { Resolve-TargetEntry $n        | ForEach-Object { $targets.Add($_) } } }
    'ByFile'  {
        # File can mix any supported entry type (hostname/IP/CIDR/range)
        if (-not (Test-Path $InputFile)) { throw "Input file not found: $InputFile" }
        Get-Content $InputFile | ForEach-Object {
            Resolve-TargetEntry $_ | ForEach-Object { $targets.Add($_) }
        }
    }
}

# Deduplicate (e.g. overlapping CIDRs) and short-circuit if nothing to do
$targets = $targets | Select-Object -Unique
$total   = $targets.Count
if ($total -eq 0) { throw "No valid targets to scan." }
Write-Host "Resolved $total target(s) to scan." -ForegroundColor Cyan

# ===========================================================================
# Ports required by the Azure Migrate appliance for agentless discovery.
# Reference: https://learn.microsoft.com/azure/migrate/migrate-support-matrix
# ===========================================================================
$portMap = @{
    Windows = @(
        @{ Port = 135;  Name = 'RPC' }          # RPC Endpoint Mapper (WMI bootstrap)
        @{ Port = 139;  Name = 'NetBIOS' }      # Legacy NetBIOS session
        @{ Port = 445;  Name = 'SMB' }          # File share / dependency inventory
        @{ Port = 5985; Name = 'WinRM-HTTP' }   # WS-Management over HTTP
        @{ Port = 5986; Name = 'WinRM-HTTPS' }  # WS-Management over HTTPS
    )
    Linux = @(
        @{ Port = 22; Name = 'SSH' }            # SSH for Linux inventory
    )
}

# Decide which port set is exercised against each host based on -OsType.
$portsToTest = switch ($OsType) {
    'Windows' { $portMap.Windows }
    'Linux'   { $portMap.Linux }
    'Both'    { $portMap.Windows + $portMap.Linux }
}

# ===========================================================================
# Per-host scan logic (used by the PS 5.1 sequential path).
# The PS 7 parallel branch below contains an inlined copy because
# ForEach-Object -Parallel cannot accept script blocks via $using:.
# ===========================================================================
$scanScript = {
    param($target, $ports, $timeout)

    # Async TCP connect with a hard timeout so closed/filtered ports don't stall the scan.
    function Test-TcpPort([string]$T, [int]$P, [int]$To) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $client.BeginConnect($T, $P, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($To), $false)) {
                try { $client.EndConnect($iar); return $true } catch { return $false }
            }
            return $false
        } catch { return $false }
        finally { $client.Close() }
    }

    # Resolve host <-> IP. If input is an IP, do reverse DNS; otherwise forward DNS.
    $hostName = ''
    $ipAddr   = $null
    try {
        if ($target -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $ipAddr = $target
            try { $hostName = [System.Net.Dns]::GetHostEntry($target).HostName } catch { }   # reverse DNS may be empty
        } else {
            $hostName = $target
            $ipAddr = ([System.Net.Dns]::GetHostAddresses($target) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                Select-Object -First 1).IPAddressToString
        }
    } catch { }

    # Quick reachability hint (some hosts block ICMP but still have ports open).
    $ping = $false
    try { $ping = Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue } catch { }

    # Build the result row; columns are added dynamically per port tested.
    $row = [ordered]@{
        IPAddress = $ipAddr
        HostName  = $hostName
        Ping      = if ($ping) { 'OK' } else { 'FAIL' }
    }

    $openCount = 0
    foreach ($p in $ports) {
        $open = Test-TcpPort -T $target -P $p.Port -To $timeout
        $row["$($p.Name)($($p.Port))"] = if ($open) { 'OPEN' } else { '-' }
        if ($open) { $openCount++ }
    }

    # A host is considered "discovery ready" if at least one required port is open.
    $row['OpenPorts']      = $openCount
    $row['DiscoveryReady'] = if ($openCount -gt 0) { 'YES' } else { 'NO' }
    [pscustomobject]$row
}

# ===========================================================================
# Execute scan
#   PS 7+  : ForEach-Object -Parallel (fast - default 50 concurrent hosts)
#   PS 5.1 : sequential loop with progress bar
# ===========================================================================
$results = @()
$useParallel = $PSVersionTable.PSVersion.Major -ge 7

if ($useParallel) {
    Write-Host "Scanning in parallel (ThrottleLimit=$ThrottleLimit)..." -ForegroundColor Cyan
    $results = $targets | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        # NOTE: logic below mirrors $scanScript above. Inlined because
        # -Parallel does not allow $using: to pass a [scriptblock].
        $target  = $_
        $ports   = $using:portsToTest
        $timeout = $using:TimeoutSeconds

        function Test-TcpPort([string]$T, [int]$P, [int]$To) {
            $client = New-Object System.Net.Sockets.TcpClient
            try {
                $iar = $client.BeginConnect($T, $P, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($To), $false)) {
                    try { $client.EndConnect($iar); return $true } catch { return $false }
                }
                return $false
            } catch { return $false }
            finally { $client.Close() }
        }

        $hostName = ''
        $ipAddr   = $null
        try {
            if ($target -match '^\d{1,3}(\.\d{1,3}){3}$') {
                $ipAddr = $target
                try { $hostName = [System.Net.Dns]::GetHostEntry($target).HostName } catch { }
            } else {
                $hostName = $target
                $ipAddr = ([System.Net.Dns]::GetHostAddresses($target) |
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                    Select-Object -First 1).IPAddressToString
            }
        } catch { }

        $ping = $false
        try { $ping = Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue } catch { }

        $row = [ordered]@{
            IPAddress = $ipAddr
            HostName  = $hostName
            Ping      = if ($ping) { 'OK' } else { 'FAIL' }
        }

        $openCount = 0
        foreach ($p in $ports) {
            $open = Test-TcpPort -T $target -P $p.Port -To $timeout
            $row["$($p.Name)($($p.Port))"] = if ($open) { 'OPEN' } else { '-' }
            if ($open) { $openCount++ }
        }

        $row['OpenPorts']      = $openCount
        $row['DiscoveryReady'] = if ($openCount -gt 0) { 'YES' } else { 'NO' }
        [pscustomobject]$row
    }
} else {
    Write-Host "Scanning sequentially (PowerShell 5.1)..." -ForegroundColor Cyan
    $i = 0
    foreach ($t in $targets) {
        $i++
        Write-Progress -Activity 'Azure Migrate Discovery Scan' -Status "Testing $t ($i / $total)" -PercentComplete (($i / $total) * 100)
        $results += & $scanScript $t $portsToTest $TimeoutSeconds
    }
    Write-Progress -Activity 'Azure Migrate Discovery Scan' -Completed
}

# ===========================================================================
# Filter + output
#   By default hide hosts that are completely silent (no ping, no open ports)
#   to keep large CIDR scans readable. -IncludeUnreachable keeps everything.
# ===========================================================================
$filtered = if ($IncludeUnreachable) {
    $results
} else {
    $results | Where-Object { $_.Ping -eq 'OK' -or $_.OpenPorts -gt 0 }
}

# Console table + persistent CSV (full unfiltered counts are still in $results below)
$filtered | Format-Table -AutoSize
$filtered | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

# Summary metrics
Write-Host ""
Write-Host "Scan complete. Results exported to: $OutputCsv" -ForegroundColor Green
$ready = ($results | Where-Object DiscoveryReady -eq 'YES').Count
$alive = ($results | Where-Object Ping           -eq 'OK').Count
Write-Host "Total scanned          : $total"
Write-Host "Responded to ping      : $alive"  -ForegroundColor Cyan
Write-Host "Discovery-ready hosts  : $ready"  -ForegroundColor Green
