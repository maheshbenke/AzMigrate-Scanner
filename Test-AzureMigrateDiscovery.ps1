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

.PARAMETER PingTimeoutMs
    Short ICMP and TCP-liveness probe timeout in milliseconds, used to
    quickly detect dead hosts and skip the full port scan. Default: 500

.PARAMETER ThrottleLimit
    Maximum parallel host scans (PS 7+ only). Default: 50.

.PARAMETER IncludeUnreachable
    Include hosts that did not respond to ping AND had no open ports.

.PARAMETER LogFile
    Path to a transcript log file capturing all console output and scan
    milestones. Default: .\AzureMigrateDiscoveryScan_<timestamp>.log

.PARAMETER OutputReport
    Path to a human-readable text report summarizing the scan (parameters,
    target count, summary metrics, and a formatted results table).
    Default: .\AzureMigrateDiscoveryScan_<timestamp>.txt

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

    [int]$PingTimeoutMs = 500,

    [int]$ThrottleLimit = 50,

    [switch]$IncludeUnreachable,

    [string]$LogFile = ".\AzureMigrateDiscoveryScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",

    [string]$OutputReport = ".\AzureMigrateDiscoveryScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

# ===========================================================================
# Start transcript log. Captures all Write-Host / pipeline output plus the
# timestamped milestones written via Write-LogMessage below.
# ===========================================================================
try {
    $logDir = Split-Path -Parent $LogFile
    if ($logDir -and -not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    Start-Transcript -Path $LogFile -Append -Force | Out-Null
    $script:TranscriptStarted = $true
} catch {
    Write-Warning "Could not start transcript log '$LogFile': $($_.Exception.Message)"
    $script:TranscriptStarted = $false
}

function Write-LogMessage {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')] [string]$Level = 'INFO'
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line -ForegroundColor Gray }
    }
}

Write-LogMessage "Azure Migrate Discovery scan starting. OsType=$OsType TimeoutSeconds=$TimeoutSeconds ThrottleLimit=$ThrottleLimit"
$script:ScanStartTime = Get-Date
Write-LogMessage ("Start time: {0:yyyy-MM-dd HH:mm:ss zzz}" -f $script:ScanStartTime)
Write-LogMessage "Log file : $LogFile"
Write-LogMessage "Output CSV: $OutputCsv"
Write-LogMessage "Output report: $OutputReport"

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
if ($total -eq 0) {
    Write-LogMessage "No valid targets to scan." -Level ERROR
    if ($script:TranscriptStarted) { try { Stop-Transcript | Out-Null } catch { } }
    throw "No valid targets to scan."
}
Write-LogMessage "Resolved $total target(s) to scan."

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
    param($target, $ports, $timeoutSec, $pingTimeoutMs)

    $timeoutMs = [int]($timeoutSec * 1000)

    # ---- DNS / IP resolution ----
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

    # ---- Fast ICMP probe (short timeout so dead hosts don't dominate the scan) ----
    $ping = $false
    $pinger = New-Object System.Net.NetworkInformation.Ping
    try {
        $reply = $pinger.Send($target, $pingTimeoutMs)
        $ping  = ($reply -and $reply.Status -eq 'Success')
    } catch { } finally { $pinger.Dispose() }

    $row = [ordered]@{
        IPAddress = $ipAddr
        HostName  = $hostName
        Ping      = if ($ping) { 'OK' } else { 'FAIL' }
    }

    # ---- TCP liveness probe: many hosts block ICMP. Try a single short TCP
    # connect to the first required port. If both ICMP and this fail, treat
    # the host as dead and skip the full port scan to save N * timeout. ----
    $alive = $ping
    if (-not $alive -and $ports.Count -gt 0) {
        $probePort   = $ports[0].Port
        $probeClient = New-Object System.Net.Sockets.TcpClient
        try {
            $probeTask = $probeClient.ConnectAsync($target, $probePort)
            if ($probeTask.Wait($pingTimeoutMs)) {
                $alive = (-not $probeTask.IsFaulted) -and $probeClient.Connected
            }
        } catch { } finally { try { $probeClient.Close() } catch { } }
    }

    if (-not $alive) {
        foreach ($p in $ports) { $row["$($p.Name)($($p.Port))"] = '-' }
        $row['OpenPorts']      = 0
        $row['DiscoveryReady'] = 'NO'
        return [pscustomobject]$row
    }

    # ---- Fan-out: connect to all ports concurrently with one shared deadline.
    # Per-host wall time is bounded by $timeoutSec instead of N * $timeoutSec. ----
    $clients = New-Object 'System.Collections.Generic.Dictionary[string,System.Net.Sockets.TcpClient]'
    $tasks   = New-Object 'System.Collections.Generic.Dictionary[string,System.Threading.Tasks.Task]'
    foreach ($p in $ports) {
        $key = "$($p.Name)($($p.Port))"
        $c   = New-Object System.Net.Sockets.TcpClient
        $clients[$key] = $c
        try { $tasks[$key] = $c.ConnectAsync($target, $p.Port) } catch { $tasks[$key] = $null }
    }

    $taskArray = @($tasks.Values | Where-Object { $_ })
    if ($taskArray.Count -gt 0) {
        try { [System.Threading.Tasks.Task]::WaitAll($taskArray, $timeoutMs) | Out-Null } catch { }
    }

    $openCount = 0
    foreach ($p in $ports) {
        $key  = "$($p.Name)($($p.Port))"
        $t    = $tasks[$key]
        $c    = $clients[$key]
        $open = $false
        if ($t -and $t.IsCompleted -and -not $t.IsFaulted -and $c.Connected) { $open = $true }
        $row[$key] = if ($open) { 'OPEN' } else { '-' }
        if ($open) { $openCount++ }
        try { $c.Close() } catch { }
    }

    $row['OpenPorts']      = $openCount
    $row['DiscoveryReady'] = if ($openCount -gt 0) { 'YES' } else { 'NO' }
    [pscustomobject]$row
}

# ===========================================================================
# Execute scan
#   PS 7+  : ForEach-Object -Parallel in batches (so progress is visible and
#            the CSV grows incrementally instead of waiting for the full run)
#   PS 5.1 : sequential loop with progress bar
# ===========================================================================
$results       = New-Object System.Collections.Generic.List[object]
$useParallel   = $PSVersionTable.PSVersion.Major -ge 7
# Keep batches small enough that the user sees progress on large scans (/22, /16)
# but large enough to amortize the per-batch ForEach-Object -Parallel overhead.
$batchSize     = [Math]::Min([Math]::Max([int]$ThrottleLimit * 2, 100), 256)
$csvHeaderDone = $false

function Write-ResultsBatch {
    param([System.Collections.IEnumerable]$Batch)
    if (-not $Batch) { return }
    if (-not $script:csvHeaderDone) {
        $Batch | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
        $script:csvHeaderDone = $true
    } else {
        $Batch | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -Append
    }
}

if ($useParallel) {
    Write-LogMessage "Scanning in parallel (ThrottleLimit=$ThrottleLimit, BatchSize=$batchSize)..."
    $processed = 0
    for ($offset = 0; $offset -lt $total; $offset += $batchSize) {
        $end   = [Math]::Min($offset + $batchSize, $total) - 1
        $slice = $targets[$offset..$end]
        Write-LogMessage ("Testing hosts {0}-{1} of {2}: {3} .. {4}" -f ($offset + 1), ($end + 1), $total, $slice[0], $slice[-1])

        $batchResults = $slice | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            # NOTE: logic below mirrors $scanScript above. Inlined because
            # -Parallel does not allow $using: to pass a [scriptblock].
            $target        = $_
            $ports         = $using:portsToTest
            $timeoutSec    = $using:TimeoutSeconds
            $pingTimeoutMs = $using:PingTimeoutMs
            $timeoutMs     = [int]($timeoutSec * 1000)

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
            $pinger = New-Object System.Net.NetworkInformation.Ping
            try {
                $reply = $pinger.Send($target, $pingTimeoutMs)
                $ping  = ($reply -and $reply.Status -eq 'Success')
            } catch { } finally { $pinger.Dispose() }

            $row = [ordered]@{
                IPAddress = $ipAddr
                HostName  = $hostName
                Ping      = if ($ping) { 'OK' } else { 'FAIL' }
            }

            $alive = $ping
            if (-not $alive -and $ports.Count -gt 0) {
                $probePort   = $ports[0].Port
                $probeClient = New-Object System.Net.Sockets.TcpClient
                try {
                    $probeTask = $probeClient.ConnectAsync($target, $probePort)
                    if ($probeTask.Wait($pingTimeoutMs)) {
                        $alive = (-not $probeTask.IsFaulted) -and $probeClient.Connected
                    }
                } catch { } finally { try { $probeClient.Close() } catch { } }
            }

            if (-not $alive) {
                foreach ($p in $ports) { $row["$($p.Name)($($p.Port))"] = '-' }
                $row['OpenPorts']      = 0
                $row['DiscoveryReady'] = 'NO'
                return [pscustomobject]$row
            }

            $clients = New-Object 'System.Collections.Generic.Dictionary[string,System.Net.Sockets.TcpClient]'
            $tasks   = New-Object 'System.Collections.Generic.Dictionary[string,System.Threading.Tasks.Task]'
            foreach ($p in $ports) {
                $key = "$($p.Name)($($p.Port))"
                $c   = New-Object System.Net.Sockets.TcpClient
                $clients[$key] = $c
                try { $tasks[$key] = $c.ConnectAsync($target, $p.Port) } catch { $tasks[$key] = $null }
            }

            $taskArray = @($tasks.Values | Where-Object { $_ })
            if ($taskArray.Count -gt 0) {
                try { [System.Threading.Tasks.Task]::WaitAll($taskArray, $timeoutMs) | Out-Null } catch { }
            }

            $openCount = 0
            foreach ($p in $ports) {
                $key  = "$($p.Name)($($p.Port))"
                $t    = $tasks[$key]
                $c    = $clients[$key]
                $open = $false
                if ($t -and $t.IsCompleted -and -not $t.IsFaulted -and $c.Connected) { $open = $true }
                $row[$key] = if ($open) { 'OPEN' } else { '-' }
                if ($open) { $openCount++ }
                try { $c.Close() } catch { }
            }

            $row['OpenPorts']      = $openCount
            $row['DiscoveryReady'] = if ($openCount -gt 0) { 'YES' } else { 'NO' }
            [pscustomobject]$row
        }

        foreach ($r in $batchResults) { $results.Add($r) }
        $processed   = $end + 1
        $batchAlive  = ($batchResults | Where-Object { $_.Ping -eq 'OK' -or $_.OpenPorts -gt 0 }).Count
        $batchToCsv  = if ($IncludeUnreachable) { $batchResults } else { $batchResults | Where-Object { $_.Ping -eq 'OK' -or $_.OpenPorts -gt 0 } }
        Write-ResultsBatch -Batch $batchToCsv
        $pct = [int](($processed / $total) * 100)
        Write-LogMessage ("Progress: {0}/{1} ({2}%) - {3} responsive in this batch" -f $processed, $total, $pct, $batchAlive)
        Write-Progress -Activity 'Azure Migrate Discovery Scan' -Status "$processed / $total" -PercentComplete $pct
    }
    Write-Progress -Activity 'Azure Migrate Discovery Scan' -Completed
} else {
    Write-LogMessage "Scanning sequentially (PowerShell 5.1)..."
    $i = 0
    $batchBuffer = New-Object System.Collections.Generic.List[object]
    foreach ($t in $targets) {
        $i++
        Write-LogMessage ("Testing {0} ({1} / {2})" -f $t, $i, $total)
        Write-Progress -Activity 'Azure Migrate Discovery Scan' -Status "Testing $t ($i / $total)" -PercentComplete (($i / $total) * 100)
        $r = & $scanScript $t $portsToTest $TimeoutSeconds $PingTimeoutMs
        $results.Add($r)
        $batchBuffer.Add($r)
        if ($batchBuffer.Count -ge $batchSize -or $i -eq $total) {
            $batchToCsv = if ($IncludeUnreachable) { $batchBuffer } else { $batchBuffer | Where-Object { $_.Ping -eq 'OK' -or $_.OpenPorts -gt 0 } }
            Write-ResultsBatch -Batch $batchToCsv
            $pct = [int](($i / $total) * 100)
            Write-LogMessage ("Progress: {0}/{1} ({2}%)" -f $i, $total, $pct)
            $batchBuffer.Clear()
        }
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

# Console table + persistent CSV (CSV was already streamed per batch above).
# Cap the on-screen table for very large scans so the terminal doesn't choke;
# the CSV and report still contain every row.
$consolePreviewMax = 200
$consoleSet = $filtered
$truncatedNote = ''
if (($filtered | Measure-Object).Count -gt $consolePreviewMax) {
    $consoleSet = $filtered | Select-Object -First $consolePreviewMax
    $truncatedNote = "... showing first $consolePreviewMax of $(($filtered | Measure-Object).Count) rows. Full results in $OutputCsv and $OutputReport."
}
$tableTextConsole = if ($consoleSet) {
    ($consoleSet | Format-Table -AutoSize | Out-String -Width 4096).TrimEnd()
} else {
    '(no rows to display)'
}
Write-Host $tableTextConsole
if ($truncatedNote) { Write-Host $truncatedNote -ForegroundColor Yellow }

# If batched writes never happened (e.g. every host filtered out), still produce
# a CSV with the expected header so downstream tooling sees a valid file.
if (-not $csvHeaderDone) {
    if ($results.Count -gt 0) {
        $results[0] | Select-Object * | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
        Clear-Content -Path $OutputCsv
        ($results[0] | Select-Object * | ConvertTo-Csv -NoTypeInformation)[0] | Set-Content -Path $OutputCsv -Encoding UTF8
    } else {
        Set-Content -Path $OutputCsv -Value '' -Encoding UTF8
    }
    $csvHeaderDone = $true
}

# Summary metrics
Write-Host ""
$script:ScanEndTime = Get-Date
$scanDuration = $script:ScanEndTime - $script:ScanStartTime
$ready = ($results | Where-Object DiscoveryReady -eq 'YES').Count
$alive = ($results | Where-Object Ping           -eq 'OK').Count
Write-LogMessage "Scan complete. Results exported to: $OutputCsv"
Write-LogMessage ("Start time            : {0:yyyy-MM-dd HH:mm:ss zzz}" -f $script:ScanStartTime)
Write-LogMessage ("End time              : {0:yyyy-MM-dd HH:mm:ss zzz}" -f $script:ScanEndTime)
Write-LogMessage ("Duration              : {0:hh\:mm\:ss\.fff}" -f $scanDuration)
Write-LogMessage "Total scanned         : $total"
Write-LogMessage "Responded to ping     : $alive"
Write-LogMessage "Discovery-ready hosts : $ready"
Write-LogMessage "Log file              : $LogFile"
Write-LogMessage "Report file           : $OutputReport"

# ===========================================================================
# Human-readable text report
# ===========================================================================
try {
    $reportDir = Split-Path -Parent $OutputReport
    if ($reportDir -and -not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }

    $reportLines = New-Object System.Collections.Generic.List[string]
    $reportLines.Add('=========================================================================')
    $reportLines.Add(' Azure Migrate Discovery Readiness Scan Report')
    $reportLines.Add('=========================================================================')
    $reportLines.Add("Generated         : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
    $reportLines.Add("Run by            : $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME")
    $reportLines.Add("PowerShell version: $($PSVersionTable.PSVersion)")
    $reportLines.Add('')
    $reportLines.Add('Parameters')
    $reportLines.Add('-------------------------------------------------------------------------')
    $reportLines.Add("  ParameterSet      : $($PSCmdlet.ParameterSetName)")
    $reportLines.Add("  OsType            : $OsType")
    $reportLines.Add("  TimeoutSeconds    : $TimeoutSeconds")
    $reportLines.Add("  ThrottleLimit     : $ThrottleLimit")
    $reportLines.Add("  IncludeUnreachable: $IncludeUnreachable")
    $reportLines.Add("  OutputCsv         : $OutputCsv")
    $reportLines.Add("  LogFile           : $LogFile")
    $reportLines.Add('')
    $reportLines.Add('Summary')
    $reportLines.Add('-------------------------------------------------------------------------')
    $reportLines.Add(("  Start time            : {0:yyyy-MM-dd HH:mm:ss zzz}" -f $script:ScanStartTime))
    $reportLines.Add(("  End time              : {0:yyyy-MM-dd HH:mm:ss zzz}" -f $script:ScanEndTime))
    $reportLines.Add(("  Duration              : {0:hh\:mm\:ss\.fff}" -f $scanDuration))
    $reportLines.Add(("  Total scanned         : {0}" -f $total))
    $reportLines.Add(("  Responded to ping     : {0}" -f $alive))
    $reportLines.Add(("  Discovery-ready hosts : {0}" -f $ready))
    $reportLines.Add(("  Rows in report        : {0}" -f ($filtered | Measure-Object).Count))
    $reportLines.Add('')
    $reportLines.Add('Results')
    $reportLines.Add('-------------------------------------------------------------------------')
    $tableText = if ($filtered) {
        ($filtered | Format-Table -AutoSize | Out-String -Width 4096).TrimEnd()
    } else {
        '(no rows to display)'
    }
    $reportLines.Add($tableText)
    $reportLines.Add('')
    $reportLines.Add('=========================================================================')
    $reportLines.Add(' End of report')
    $reportLines.Add('=========================================================================')

    Set-Content -Path $OutputReport -Value $reportLines -Encoding UTF8
} catch {
    Write-LogMessage "Failed to write report '$OutputReport': $($_.Exception.Message)" -Level WARN
}

if ($script:TranscriptStarted) {
    try { Stop-Transcript | Out-Null } catch { }
}
