@echo off
REM =============================================================================
REM  Test-Network.cmd: one interactive toolkit, three probes.
REM
REM    1  ping sweep       one pass, lists what answered and what did not
REM    2  watch            continuous, announces addresses as they come alive
REM    3  TCP port scan    discovery pass, then open ports per host
REM
REM  Self-contained. This batch half only finds a PowerShell and hands off;
REM  everything below the #PS_START marker is PowerShell and is never parsed
REM  by cmd. Prefers PowerShell 7 and falls back to Windows PowerShell 5.1,
REM  since nothing here requires 7.
REM =============================================================================
title Network probe toolkit
set "TOOLDIR=%~dp0"
where pwsh.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    pwsh.exe -NoLogo -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create($($c=Get-Content '%~f0'; $i=($c|Select-String '^#PS_START').LineNumber; ($c[$i..($c.Count-1)])-join[Environment]::NewLine)))"
) else (
    powershell.exe -NoLogo -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create($($c=Get-Content '%~f0'; $i=($c|Select-String '^#PS_START').LineNumber; ($c[$i..($c.Count-1)])-join[Environment]::NewLine)))"
)
exit /b
#PS_START
# =============================================================================
#  PowerShell half. cmd never reaches this, because the launcher above exits
#  first.
#
#  Three tools behind one menu:
#    1  ping sweep       one pass, lists what answered and what didn't
#    2  watch            continuous, announces addresses as they come alive
#    3  TCP port scan    two-phase discovery + port scan, reports open ports
#
#  Everything shares one address parser, so all three accept the same
#  formats, mixed freely:
#       10.1.30.57                  single address
#       dsp.local                   hostname (resolved at parse time)
#       10.1.30.60-10.1.30.74       range
#       10.1.30.60-74               range, last octet only
#       10.1.30.0/23                CIDR
#       10.1.30.0 255.255.254.0     dotted mask
#
#  Runs on PowerShell 7 or Windows PowerShell 5.1. All concurrency is
#  async-task based rather than runspace based, so nothing here needs 7.
# =============================================================================

$ErrorActionPreference = 'Stop'

$ToolDir = $env:TOOLDIR
if ([string]::IsNullOrWhiteSpace($ToolDir)) { $ToolDir = (Get-Location).Path }

# --- port labels. Generic IT entries are well established; the ones marked
# --- (verify) are convenience only. Confirm them against the vendor doc for
# --- the firmware you are actually on.
$Labels = @{
    21 = 'FTP';    22 = 'SSH';   23 = 'Telnet'; 25 = 'SMTP';  53 = 'DNS'
    67 = 'DHCP';   69 = 'TFTP';  80 = 'HTTP';   111 = 'RPCbind'
    123 = 'NTP';   135 = 'MSRPC'; 139 = 'NetBIOS-SSN'; 389 = 'LDAP'
    443 = 'HTTPS'; 445 = 'SMB';  515 = 'LPD';   548 = 'AFP';  554 = 'RTSP'
    587 = 'SMTP-Sub'; 623 = 'IPMI/BMC'; 636 = 'LDAPS'; 993 = 'IMAPS'
    1433 = 'MSSQL'; 1723 = 'PPTP'; 1935 = 'RTMP'; 2000 = 'Cisco-SCCP'
    3306 = 'MySQL'; 3389 = 'RDP'; 5000 = 'UPnP/misc'; 5001 = 'alt-HTTP/iperf'
    5060 = 'SIP';  5061 = 'SIP-TLS'; 5900 = 'VNC'; 5985 = 'WinRM-HTTP'
    5986 = 'WinRM-HTTPS'; 8000 = 'alt-HTTP'; 8080 = 'alt-HTTP'
    8443 = 'alt-HTTPS'; 8554 = 'alt-RTSP'; 9000 = 'alt-HTTP'
    1702 = 'Q-SYS QRC legacy (verify)'; 1710 = 'Q-SYS QRC (verify)'
    41794 = 'Crestron CIP (verify)'; 41795 = 'Crestron CTP console (verify)'
    5959 = 'NDI discovery server (verify)'; 6970 = 'RTP range (verify)'
    7000 = 'AirPlay (verify)'
}

$CommonPorts = @(
    21, 22, 23, 25, 53, 69, 80, 111, 135, 139, 389, 443, 445, 515, 548, 554,
    587, 623, 636, 993, 1433, 1702, 1710, 1723, 1935, 2000, 3306, 3389, 5000,
    5001, 5060, 5061, 5900, 5959, 5985, 5986, 6970, 7000, 8000, 8080, 8443,
    8554, 9000, 41794, 41795
)

# Cheap liveness probe set: an RST from any of these proves the host exists.
# That is better evidence than ICMP, which plenty of AV gear drops.
$DiscoveryPorts = @(22, 23, 80, 135, 443, 445, 3389, 8080)

$MaxAddresses = 65536

#region ---------------------------------------------------- address plumbing

function ConvertTo-UInt32Ip ([string] $Ip) {
    $b = ([System.Net.IPAddress]::Parse($Ip.Trim())).GetAddressBytes()
    [Array]::Reverse($b)
    [System.BitConverter]::ToUInt32($b, 0)
}

function ConvertFrom-UInt32Ip ([uint32] $Value) {
    $b = [System.BitConverter]::GetBytes($Value)
    [Array]::Reverse($b)
    ([System.Net.IPAddress]::new($b)).ToString()
}

function Get-MaskInt ([int] $Prefix) {
    if ($Prefix -eq 0)  { return [uint32] 0 }
    if ($Prefix -eq 32) { return [uint32]::MaxValue }
    [uint32] ([uint64] ([Math]::Pow(2, $Prefix) - 1) * [uint64] [Math]::Pow(2, 32 - $Prefix))
}

function ConvertTo-Prefix ([string] $Mask) {
    [uint32] $m = ConvertTo-UInt32Ip $Mask
    $bits = 0
    [uint32] $t = $m
    # Shift rather than divide. [uint32]($t / 2) goes through a double and
    # rounds half to even, which silently miscounts every odd value on the way
    # down and reports a contiguous mask as non-contiguous.
    while ($t) { $bits += [int] ($t -band 1); $t = [uint32] ($t -shr 1) }
    if ($m -ne (Get-MaskInt $bits)) { throw "non-contiguous mask: $Mask" }
    $bits
}

# One line in, the numeric addresses it covers out. Bad lines are reported and
# skipped rather than killing the run.
function Expand-AddressLine ([string] $Line) {
    $s = $Line.Trim()
    if (-not $s -or $s.StartsWith('#')) { return }

    try {
        # CIDR  10.1.30.0/23
        if ($s -match '^(\d{1,3}(?:\.\d{1,3}){3})\s*/\s*(\d{1,2})$') {
            $p = [int] $Matches[2]
            if ($p -gt 32) { throw "prefix must be 0-32" }
            $mask = Get-MaskInt $p
            $net  = (ConvertTo-UInt32Ip $Matches[1]) -band $mask
            $bc   = $net -bor ([uint32]::MaxValue -bxor $mask)
            if ($p -le 30) { $a = $net + 1; $b = $bc - 1 } else { $a = $net; $b = $bc }
        }
        # dotted mask  10.1.30.0 255.255.254.0   (space or slash separated)
        elseif ($s -match '^(\d{1,3}(?:\.\d{1,3}){3})[\s/]+(\d{1,3}(?:\.\d{1,3}){3})$') {
            $p    = ConvertTo-Prefix $Matches[2]
            $mask = Get-MaskInt $p
            $net  = (ConvertTo-UInt32Ip $Matches[1]) -band $mask
            $bc   = $net -bor ([uint32]::MaxValue -bxor $mask)
            if ($p -le 30) { $a = $net + 1; $b = $bc - 1 } else { $a = $net; $b = $bc }
        }
        # full range  10.1.30.60-10.1.30.74
        elseif ($s -match '^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$') {
            $a = ConvertTo-UInt32Ip $Matches[1]
            $b = ConvertTo-UInt32Ip $Matches[2]
            if ($a -gt $b) { $x = $a; $a = $b; $b = $x }
        }
        # last-octet range  10.1.30.60-74
        elseif ($s -match '^(\d{1,3}(?:\.\d{1,3}){2})\.(\d{1,3})\s*-\s*(\d{1,3})$') {
            $lo = [int] $Matches[2]; $hi = [int] $Matches[3]
            if ($lo -gt $hi) { $x = $lo; $lo = $hi; $hi = $x }
            if ($hi -gt 255) { throw "octet out of range" }
            $a = ConvertTo-UInt32Ip ("{0}.{1}" -f $Matches[1], $lo)
            $b = ConvertTo-UInt32Ip ("{0}.{1}" -f $Matches[1], $hi)
        }
        # single address
        elseif ($s -match '^\d{1,3}(?:\.\d{1,3}){3}$') {
            $a = ConvertTo-UInt32Ip $s
            $b = $a
        }
        # hostname, resolved here so everything downstream stays numeric
        else {
            $resolved = @([System.Net.Dns]::GetHostAddresses($s) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' })
            if (-not $resolved.Count) { throw "no IPv4 address" }
            foreach ($r in $resolved) { ConvertTo-UInt32Ip $r.IPAddressToString }
            return
        }
    }
    catch {
        Write-Host ("    skipped '{0}': {1}" -f $s, $_.Exception.Message) -ForegroundColor DarkYellow
        return
    }

    for ($i = $a; $i -le $b; $i++) { $i }
}

# Consecutive numbers back into "first-last" strings for display.
function Compress-AddressList ([uint32[]] $Numbers) {
    if (-not $Numbers.Count) { return @() }
    $sorted = @($Numbers | Sort-Object)
    $out    = [System.Collections.Generic.List[string]]::new()
    $start  = $sorted[0]
    $prev   = $sorted[0]
    # Step with an index. On a one-element array $sorted[1..0] counts backwards
    # and yields a phantom $null, which lands in the output as a duplicate.
    for ($k = 1; $k -lt $sorted.Count; $k++) {
        $n = $sorted[$k]
        if ($n -eq $prev + 1) { $prev = $n; continue }
        if ($start -eq $prev) { $out.Add((ConvertFrom-UInt32Ip $start)) }
        else { $out.Add(('{0}-{1}' -f (ConvertFrom-UInt32Ip $start), (ConvertFrom-UInt32Ip $prev))) }
        $start = $n; $prev = $n
    }
    if ($start -eq $prev) { $out.Add((ConvertFrom-UInt32Ip $start)) }
    else { $out.Add(('{0}-{1}' -f (ConvertFrom-UInt32Ip $start), (ConvertFrom-UInt32Ip $prev))) }
    $out
}

#endregion

#region ---------------------------------------------------- prompt plumbing

function Read-Default ([string] $Prompt, [string] $Default) {
    $v = Read-Host ("  {0} [{1}]" -f $Prompt, $Default)
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    $v.Trim()
}

function Read-IntDefault ([string] $Prompt, [int] $Default, [int] $Min, [int] $Max) {
    while ($true) {
        $v = Read-Default $Prompt $Default
        $n = 0
        if ([int]::TryParse($v, [ref] $n) -and $n -ge $Min -and $n -le $Max) { return $n }
        Write-Host ("    whole number between {0} and {1}." -f $Min, $Max) -ForegroundColor DarkYellow
    }
}

function Read-YesNo ([string] $Prompt, [bool] $Default) {
    if ($Default) { $hint = 'Y/n' } else { $hint = 'y/N' }
    while ($true) {
        $v = Read-Host ("  {0} [{1}]" -f $Prompt, $hint)
        if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
        if ($v -match '^[yY]') { return $true }
        if ($v -match '^[nN]') { return $false }
        Write-Host '    y or n.' -ForegroundColor DarkYellow
    }
}

function Read-AddressLines ([string] $Purpose) {
    Write-Host ''
    Write-Host ("  Enter {0}, one per line. Blank line when done." -f $Purpose) -ForegroundColor DarkGray
    $lines = [System.Collections.Generic.List[string]]::new()
    while ($true) {
        Write-Host '    > ' -NoNewline
        $l = Read-Host
        if ([string]::IsNullOrWhiteSpace($l)) { break }
        $lines.Add($l)
    }
    $lines
}

# Asks where the addresses come from, expands them, subtracts exclusions,
# returns a sorted uint32 array. $null if the user backs out.
function Get-AddressSet {
    Write-Host ''
    Write-Host '  Address formats, mixed freely:' -ForegroundColor DarkGray
    Write-Host '    10.1.30.57   dsp.local   10.1.30.60-74   10.1.30.0/23   10.1.30.0 255.255.254.0' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '    [1] Type them in' -ForegroundColor Gray
    Write-Host '    [2] Read from a text file' -ForegroundColor Gray
    Write-Host '    [0] Back to the menu' -ForegroundColor Gray

    $lines = $null
    while ($null -eq $lines) {
        $choice = Read-Default 'Choice' '1'
        switch ($choice) {
            '0' { return $null }
            '1' { $lines = Read-AddressLines 'addresses' }
            '2' {
                $path = (Read-Default 'Path to the list' '').Trim('"')
                if (Test-Path -LiteralPath $path) { $lines = @(Get-Content -LiteralPath $path) }
                else { Write-Host '    cannot find that file.' -ForegroundColor DarkYellow }
            }
            default { Write-Host '    1, 2 or 0.' -ForegroundColor DarkYellow }
        }
    }

    $pool = [System.Collections.Generic.HashSet[uint32]]::new()
    foreach ($l in $lines) { foreach ($n in Expand-AddressLine $l) { [void] $pool.Add($n) } }

    if (-not $pool.Count) {
        Write-Host '  Nothing usable in that list.' -ForegroundColor Red
        return $null
    }

    Write-Host ("  {0} address(es) in the pool." -f $pool.Count) -ForegroundColor Cyan

    if (Read-YesNo 'Exclude anything from that pool?' $false) {
        $ex = [System.Collections.Generic.HashSet[uint32]]::new()
        foreach ($l in (Read-AddressLines 'addresses to skip')) {
            foreach ($n in Expand-AddressLine $l) { [void] $ex.Add($n) }
        }
        if ($ex.Count) {
            $before = $pool.Count
            [void] $pool.ExceptWith($ex)
            Write-Host ("  {0} excluded, {1} remaining." -f ($before - $pool.Count), $pool.Count) -ForegroundColor Cyan
        }
    }

    if (-not $pool.Count) {
        Write-Host '  Nothing left after exclusions.' -ForegroundColor Red
        return $null
    }
    if ($pool.Count -gt $MaxAddresses) {
        Write-Host ("  {0} addresses is past the {1} ceiling. Check your prefix." -f $pool.Count, $MaxAddresses) -ForegroundColor Red
        return $null
    }

    , @($pool | Sort-Object)
}

function Save-Lines ([string[]] $Lines, [string] $DefaultName, [string] $What) {
    if (-not (Read-YesNo ("Save {0} to a file?" -f $What) $false)) { return }
    $path = (Read-Default 'Path' (Join-Path $ToolDir $DefaultName)).Trim('"')
    try {
        Set-Content -LiteralPath $path -Value $Lines -Encoding ASCII
        Write-Host ("  Written to {0}" -f $path) -ForegroundColor Cyan
    }
    catch { Write-Host ("  Could not write it: {0}" -f $_.Exception.Message) -ForegroundColor Red }
}

#endregion

#region ---------------------------------------------------- probe engines

# One chunk of ICMP, all in flight at once. Returns the addresses that answered.
function Invoke-PingChunk ([string[]] $Addresses, [int] $TimeoutMs) {
    $pingers = New-Object 'System.Collections.Generic.List[System.Net.NetworkInformation.Ping]'
    $tasks   = New-Object 'System.Collections.Generic.List[System.Threading.Tasks.Task]'
    try {
        foreach ($a in $Addresses) {
            $p = [System.Net.NetworkInformation.Ping]::new()
            $pingers.Add($p)
            $tasks.Add($p.SendPingAsync($a, $TimeoutMs))
        }
        # WaitAll throws if any task faulted; the per-task status below is what
        # actually decides, so swallow it.
        try { [void] [System.Threading.Tasks.Task]::WaitAll($tasks.ToArray(), $TimeoutMs + 1000) } catch { }
        for ($i = 0; $i -lt $tasks.Count; $i++) {
            if ($tasks[$i].Status -eq 'RanToCompletion' -and $tasks[$i].Result.Status -eq 'Success') {
                $Addresses[$i]
            }
        }
    }
    finally { foreach ($p in $pingers) { $p.Dispose() } }
}

function Invoke-PingSweep ([string[]] $Addresses, [int] $TimeoutMs, [int] $Batch, [bool] $Live) {
    $hits = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Addresses.Count; $i += $Batch) {
        $end   = [Math]::Min($i + $Batch - 1, $Addresses.Count - 1)
        $chunk = $Addresses[$i .. $end]
        foreach ($h in Invoke-PingChunk $chunk $TimeoutMs) {
            $hits.Add($h)
            if ($Live) { Write-Host ("    [+] {0}" -f $h) -ForegroundColor Green }
        }
        if (-not $Live) {
            Write-Progress -Activity 'Ping sweep' -Status ("{0} / {1}" -f ($end + 1), $Addresses.Count) `
                -PercentComplete ([Math]::Round((($end + 1) / $Addresses.Count) * 100))
        }
    }
    Write-Progress -Activity 'Ping sweep' -Completed
    $hits
}

# One chunk of TCP connects, all in flight at once.
#   Open     = handshake completed
#   Closed   = RST, i.e. something is there and refused
#   Filtered = nothing came back inside the timeout
function Invoke-TcpChunk ([string[]] $Hosts, [int[]] $Ports, [int64] $First, [int64] $Last, [int] $TimeoutMs) {
    $clients = New-Object 'System.Collections.Generic.List[System.Net.Sockets.TcpClient]'
    $tasks   = New-Object 'System.Collections.Generic.List[System.Threading.Tasks.Task]'
    $pairs   = New-Object 'System.Collections.Generic.List[object]'
    $hc      = $Hosts.Count

    try {
        for ($k = $First; $k -le $Last; $k++) {
            # Breadth-first: adjacent work items land on different hosts, so the
            # concurrency spreads across the subnet instead of dumping 256
            # simultaneous SYNs on one camera.
            $ip   = $Hosts[$k % $hc]
            $port = $Ports[[Math]::Floor($k / $hc)]
            $c    = [System.Net.Sockets.TcpClient]::new()
            # Abortive close so our sockets skip TIME_WAIT. The Windows dynamic
            # port pool is what actually limits a big sweep.
            $c.LingerState = [System.Net.Sockets.LingerOption]::new($true, 0)
            $clients.Add($c)
            $pairs.Add([pscustomobject] @{ Target = $ip; Port = $port })
            $tasks.Add($c.ConnectAsync($ip, $port))
        }

        try { [void] [System.Threading.Tasks.Task]::WaitAll($tasks.ToArray(), $TimeoutMs) } catch { }

        for ($i = 0; $i -lt $tasks.Count; $i++) {
            $state = 'Filtered'
            if ($tasks[$i].IsFaulted) { $state = 'Closed' }
            elseif ($tasks[$i].Status -eq 'RanToCompletion') {
                if ($clients[$i].Connected) { $state = 'Open' } else { $state = 'Closed' }
            }
            [pscustomobject] @{
                Target  = $pairs[$i].Target
                Port    = $pairs[$i].Port
                State   = $state
                Service = $Labels[[int] $pairs[$i].Port]
            }
        }
    }
    finally { foreach ($c in $clients) { $c.Dispose() } }
}

function Invoke-TcpScan ([string[]] $Hosts, [int[]] $Ports, [int] $TimeoutMs, [int] $Batch, [string] $Activity) {
    $total   = [int64] $Hosts.Count * $Ports.Count
    $results = [System.Collections.Generic.List[object]]::new()
    for ($i = [int64] 0; $i -lt $total; $i += $Batch) {
        $end = [Math]::Min($i + $Batch - 1, $total - 1)
        foreach ($r in Invoke-TcpChunk $Hosts $Ports $i $end $TimeoutMs) { $results.Add($r) }
        $open = @($results | Where-Object { $_.State -eq 'Open' }).Count
        Write-Progress -Activity $Activity `
            -Status ("{0} / {1} checked - {2} open" -f ($end + 1), $total, $open) `
            -PercentComplete ([Math]::Round((($end + 1) / $total) * 100))
    }
    Write-Progress -Activity $Activity -Completed
    $results
}

#endregion

#region ---------------------------------------------------- mode 1: sweep

function Invoke-SweepMode {
    Write-Host ''
    Write-Host '  --- Ping sweep -------------------------------------' -ForegroundColor Cyan

    $numbers = Get-AddressSet
    if ($null -eq $numbers) { return }

    $addresses = @($numbers | ForEach-Object { ConvertFrom-UInt32Ip $_ })
    Write-Host ''
    $timeout = Read-IntDefault 'Reply timeout in ms' 500 50 30000
    $batch   = Read-IntDefault 'Pings in flight at once' 64 1 1024

    Write-Host ''
    Write-Host ("  Sweeping {0} addresses, {1} to {2}" -f $addresses.Count, $addresses[0], $addresses[-1]) -ForegroundColor Cyan
    Write-Host ''
    $sw   = [System.Diagnostics.Stopwatch]::StartNew()
    $hits = @(Invoke-PingSweep $addresses $timeout $batch $true)
    $sw.Stop()

    $aliveSet = [System.Collections.Generic.HashSet[uint32]]::new()
    foreach ($h in $hits) { [void] $aliveSet.Add((ConvertTo-UInt32Ip $h)) }
    $quiet = @($numbers | Where-Object { -not $aliveSet.Contains($_) })

    Write-Host ''
    Write-Host ("  Done in {0:F1}s. {1} of {2} answered, {3} silent." -f `
        $sw.Elapsed.TotalSeconds, $hits.Count, $addresses.Count, $quiet.Count) -ForegroundColor Cyan
    Write-Host ''

    $upLines = @($hits | Sort-Object { ConvertTo-UInt32Ip $_ })
    if ($upLines.Count) {
        Write-Host '  Responded:' -ForegroundColor White
        foreach ($u in $upLines) { Write-Host ("    {0}" -f $u) -ForegroundColor Green }
        Write-Host ''
    }

    $gapLines = @(Compress-AddressList $quiet)
    if ($gapLines.Count) {
        Write-Host ("  Silent, collapsed to {0} range(s):" -f $gapLines.Count) -ForegroundColor White
        foreach ($g in $gapLines) { Write-Host ("    {0}" -f $g) -ForegroundColor DarkGray }
        Write-Host ''
        Write-Host '  Anything firewalled against ICMP, or powered down when this ran,' -ForegroundColor DarkGray
        Write-Host '  looks free here but is not. Cross-check DHCP leases before you claim' -ForegroundColor DarkGray
        Write-Host '  any of it.' -ForegroundColor DarkGray
        Write-Host ''
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmm'
    if ($upLines.Count)  { Save-Lines $upLines  ("responded-{0}.txt" -f $stamp) 'the responders' }
    if ($gapLines.Count) { Save-Lines $gapLines ("free-{0}.txt" -f $stamp)      'the silent ranges' }
}

#endregion

#region ---------------------------------------------------- mode 2: watch

function Invoke-WatchMode {
    Write-Host ''
    Write-Host '  --- Watch for new hosts ----------------------------' -ForegroundColor Cyan
    Write-Host '  First pass is a silent baseline. After that, every address that' -ForegroundColor DarkGray
    Write-Host '  starts answering is printed and logged. Ctrl-C to stop.' -ForegroundColor DarkGray

    $numbers = Get-AddressSet
    if ($null -eq $numbers) { return }

    $addresses = @($numbers | ForEach-Object { ConvertFrom-UInt32Ip $_ })
    Write-Host ''
    $timeout     = Read-IntDefault 'Reply timeout in ms' 500 50 30000
    $batch       = Read-IntDefault 'Pings in flight at once' 64 1 1024
    $rest        = Read-IntDefault 'Seconds between passes' 30 0 86400
    $transitions = Read-YesNo 'Also report addresses that go away?' $false
    $logPath     = (Read-Default 'Log file' (Join-Path $ToolDir 'found.log')).Trim('"')

    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $pass = 0

    Write-Host ''
    Write-Host ("  Watching {0} addresses, {1} to {2}" -f $addresses.Count, $addresses[0], $addresses[-1]) -ForegroundColor Cyan
    Write-Host '  Taking baseline...' -ForegroundColor DarkGray

    while ($true) {
        $pass++
        $alive = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($h in (Invoke-PingSweep $addresses $timeout $batch $false)) { [void] $alive.Add($h) }

        if ($pass -eq 1) {
            foreach ($ip in $alive) { [void] $seen.Add($ip) }
            Write-Host ("  Baseline: {0} of {1} already responding (not reported)." -f $alive.Count, $addresses.Count) -ForegroundColor Cyan
            Write-Host '  Watching for new arrivals...' -ForegroundColor Cyan
            Write-Host ''
        }
        else {
            $new = @($alive | Where-Object { -not $seen.Contains($_) } | Sort-Object { ConvertTo-UInt32Ip $_ })
            foreach ($ip in $new) {
                [void] $seen.Add($ip)
                $line = '{0:yyyy-MM-dd HH:mm:ss}  UP    {1}' -f (Get-Date), $ip
                Write-Host ''
                Write-Host ("  " + $line) -ForegroundColor Green
                try { Add-Content -LiteralPath $logPath -Value $line } catch { }
            }

            if ($transitions) {
                $gone = @($seen | Where-Object { -not $alive.Contains($_) } | Sort-Object { ConvertTo-UInt32Ip $_ })
                foreach ($ip in $gone) {
                    [void] $seen.Remove($ip)
                    $line = '{0:yyyy-MM-dd HH:mm:ss}  GONE  {1}' -f (Get-Date), $ip
                    Write-Host ''
                    Write-Host ("  " + $line) -ForegroundColor DarkYellow
                    try { Add-Content -LiteralPath $logPath -Value $line } catch { }
                }
            }
        }

        Write-Host '.' -NoNewline
        Start-Sleep -Seconds $rest
    }
}

#endregion

#region ---------------------------------------------------- mode 3: ports

function Read-PortSet {
    Write-Host ''
    Write-Host ("    [1] Common AV / IT set ({0} ports)" -f $CommonPorts.Count) -ForegroundColor Gray
    Write-Host '    [2] Type a list, e.g. 22,23,80,443,8000-8100' -ForegroundColor Gray
    Write-Host '    [3] Everything, 1-65535' -ForegroundColor Gray

    while ($true) {
        $c = Read-Default 'Ports' '1'
        if ($c -eq '1') { return , @($CommonPorts | Sort-Object) }
        if ($c -eq '3') {
            Write-Host '    65535 ports per host. On more than a couple of hosts this runs' -ForegroundColor DarkYellow
            Write-Host '    for hours.' -ForegroundColor DarkYellow
            if (Read-YesNo 'Sure?' $false) { return , @(1..65535) }
            continue
        }
        if ($c -eq '2') {
            $spec = Read-Default 'Port list' '22,23,80,443'
            $set  = [System.Collections.Generic.HashSet[int]]::new()
            $ok   = $true
            foreach ($piece in ($spec -split '[,;]' | Where-Object { $_.Trim() })) {
                $piece = $piece.Trim()
                if ($piece -match '^(\d{1,5})\s*-\s*(\d{1,5})$') {
                    $lo = [int] $Matches[1]; $hi = [int] $Matches[2]
                    if ($lo -gt $hi) { $x = $lo; $lo = $hi; $hi = $x }
                    if ($lo -lt 1 -or $hi -gt 65535) { $ok = $false; break }
                    $lo..$hi | ForEach-Object { [void] $set.Add($_) }
                }
                elseif ($piece -match '^\d{1,5}$' -and [int] $piece -ge 1 -and [int] $piece -le 65535) {
                    [void] $set.Add([int] $piece)
                }
                else { $ok = $false; break }
            }
            if ($ok -and $set.Count) { return , @($set | Sort-Object) }
            Write-Host '    could not read that port list.' -ForegroundColor DarkYellow
            continue
        }
        Write-Host '    1, 2 or 3.' -ForegroundColor DarkYellow
    }
}

function Invoke-PortMode {
    Write-Host ''
    Write-Host '  --- TCP port scan ----------------------------------' -ForegroundColor Cyan
    Write-Host '  TCP only. Dante control and audio, PTP, mDNS discovery and SNMP' -ForegroundColor DarkGray
    Write-Host '  are UDP and will never show up here.' -ForegroundColor DarkGray

    $numbers = Get-AddressSet
    if ($null -eq $numbers) { return }

    $addresses = @($numbers | ForEach-Object { ConvertFrom-UInt32Ip $_ })
    $ports     = Read-PortSet

    Write-Host ''
    $timeout = Read-IntDefault 'Connect timeout in ms' 400 50 30000
    $batch   = Read-IntDefault 'Sockets in flight at once' 256 1 1024
    $discover = $true
    if ($addresses.Count -gt 1) {
        $discover = Read-YesNo 'Probe for live hosts first? (much faster on a sparse subnet)' $true
    }

    Write-Host ''
    Write-Host ("  {0} address(es), {1} port(s) each" -f $addresses.Count, $ports.Count) -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # --- phase 1: discovery ---
    $live = $addresses
    if ($discover -and $addresses.Count -gt 1) {
        Write-Host ("  Discovery: {0} ports per host..." -f $DiscoveryPorts.Count) -ForegroundColor DarkGray
        $d = Invoke-TcpScan $addresses $DiscoveryPorts ([Math]::Min($timeout, 500)) $batch 'Discovery'

        # Open or Closed both mean something answered. Filtered everywhere means
        # nothing is there.
        $live = @($d | Where-Object { $_.State -eq 'Open' -or $_.State -eq 'Closed' } |
                  Select-Object -ExpandProperty Target -Unique)

        # ICMP as a second chance for hosts that dropped every TCP probe.
        $quiet = @($addresses | Where-Object { $_ -notin $live })
        if ($quiet.Count) {
            $pingLive = @(Invoke-PingSweep $quiet 500 $batch $false)
            if ($pingLive.Count) { $live = @($live) + @($pingLive) }
        }

        $live = @($live | Sort-Object { ConvertTo-UInt32Ip $_ } -Unique)
        Write-Host ("  Discovery found {0} live host(s) in {1:F1}s" -f $live.Count, $sw.Elapsed.TotalSeconds) -ForegroundColor Cyan
        if (-not $live.Count) {
            Write-Host '  Nothing answered. Either this is the wrong VLAN, or every probe' -ForegroundColor Yellow
            Write-Host '  is being dropped. Try again with the discovery phase turned off.' -ForegroundColor Yellow
            return
        }
    }

    # --- phase 2: the port scan ---
    $work  = [int64] $live.Count * $ports.Count
    $worst = [TimeSpan]::FromMilliseconds(($work / $batch) * $timeout)
    Write-Host ("  Scanning {0} host(s) x {1} ports = {2} checks, {3} at a time" -f $live.Count, $ports.Count, $work, $batch) -ForegroundColor Cyan
    Write-Host ("  Worst case {0:hh\:mm\:ss} if fully filtered; far faster if hosts return RSTs." -f $worst) -ForegroundColor DarkGray

    $results = Invoke-TcpScan $live $ports $timeout $batch 'TCP scan'
    $sw.Stop()

    $open  = @($results | Where-Object { $_.State -eq 'Open' })
    $lines = [System.Collections.Generic.List[string]]::new()

    foreach ($grp in ($open | Group-Object Target | Sort-Object { ConvertTo-UInt32Ip $_.Name })) {
        Write-Host ''
        Write-Host ("  {0}" -f $grp.Name) -ForegroundColor White
        foreach ($hit in ($grp.Group | Sort-Object Port)) {
            $svc = ''
            if ($hit.Service) { $svc = " ($($hit.Service))" }
            Write-Host ("    OPEN  {0}{1}" -f $hit.Port, $svc) -ForegroundColor Green
            $lines.Add(("{0}`t{1}{2}" -f $grp.Name, $hit.Port, $svc))
        }
    }

    $closed   = @($results | Where-Object { $_.State -eq 'Closed' }).Count
    $filtered = @($results | Where-Object { $_.State -eq 'Filtered' }).Count

    Write-Host ''
    Write-Host ("  Done in {0:hh\:mm\:ss}. {1} open across {2} host(s); {3} closed, {4} filtered." -f `
        $sw.Elapsed, $open.Count, @($open | Group-Object Target).Count, $closed, $filtered) -ForegroundColor Cyan
    Write-Host ''

    if ($lines.Count) {
        Save-Lines $lines ("openports-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmm')) 'the open ports'
    }
}

#endregion

#region ---------------------------------------------------- menu

function Show-Banner {
    Write-Host ''
    Write-Host '  ==========================================' -ForegroundColor Cyan
    Write-Host '            Network probe toolkit           ' -ForegroundColor Cyan
    Write-Host '  ==========================================' -ForegroundColor Cyan
    Write-Host ("  PowerShell {0}" -f $PSVersionTable.PSVersion) -ForegroundColor DarkGray
    Write-Host ''
}

Clear-Host
Show-Banner

while ($true) {
    Write-Host '  [1] Ping sweep      one pass, what answered and what did not' -ForegroundColor Gray
    Write-Host '  [2] Watch           continuous, shout when something appears' -ForegroundColor Gray
    Write-Host '  [3] TCP port scan   discovery pass, then open ports per host' -ForegroundColor Gray
    Write-Host '  [Q] Quit' -ForegroundColor Gray
    Write-Host ''

    $choice = Read-Default 'Choice' '1'
    switch ($choice.ToUpper()) {
        '1' { Invoke-SweepMode }
        '2' { Invoke-WatchMode }
        '3' { Invoke-PortMode }
        'Q' { Write-Host ''; exit 0 }
        default { Write-Host '  1, 2, 3 or Q.' -ForegroundColor DarkYellow }
    }

    Write-Host ''
    Write-Host '  ------------------------------------------' -ForegroundColor DarkGray
    Write-Host ''
}

#endregion
