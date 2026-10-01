# Read-only Windows process evidence for fm-session-lock-lib.sh.
# Usage: powershell.exe -NoProfile -NonInteractive -File <this-file>
#          -Mode ancestry|process -ProcessId <native-Windows-pid>
#          [-MsysAncestry <comma-separated-native-pids-from-MSYS-proc>]
# Output: pid|parent-pid|executable-path|interpreter-script, one process per line.
# Paths use forward slashes; '-' denotes an unavailable path or no script.
# Exit 3 means the requested process is absent; 2 means evidence is unavailable.
# Keep absence distinct from PowerShell's own launch/parameter failure (exit 1).
# Never consult agent environment markers or evaluate a process's command line.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('ancestry', 'process')]
    [string]$Mode,
    [uint32]$ProcessId = 0,
    [string]$MsysAncestry = ''
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Process-Row($Process) {
    $executable = $Process.ExecutablePath
    if ([string]::IsNullOrEmpty($executable)) { $executable = '-' }
    $script = '-'
    # Only argv[1] of an actual interpreter is a possible script, never a
    # prompt, -e program, later argument, or inherited environment variable.
    # Quoted paths with spaces are supported; escaped quotes and control
    # characters are deliberately not interpreted as executable evidence.
    if ($Process.Name -match '^(node|python|python3)\.exe$' -and
        $Process.CommandLine -match '^\s*(?:"[^"\r\n]+"|[^\s"]+)\s+(?:"([^"\r\n]+)"|([^\s"]+))(?:\s|$)') {
        $candidate = $Matches[1]
        if (!$candidate) { $candidate = $Matches[2] }
        if ($candidate -match '^[A-Za-z]:[\\/]') { $script = $candidate }
    }
    foreach ($value in @($executable, $script)) {
        if ($value -match '[|\x00-\x1f]') { throw 'Invalid process path' }
    }
    '{0}|{1}|{2}|{3}' -f $Process.ProcessId, $Process.ParentProcessId,
        $executable.Replace('\', '/'), $script.Replace('\', '/')
}

try {
    if ($Mode -eq 'process') {
        if ($ProcessId -eq 0) { exit 2 }
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -OperationTimeoutSec 3
        if (!$process) { exit 3 }
        if (!$process.ExecutablePath) { exit 2 }
        Process-Row $process
    } else {
        # One fresh snapshot avoids sixteen separate PowerShell/CIM startups.
        # MSYS retains its PID across exec while replacing the native process.
        # Only the caller's /proc-derived edges may bridge a dead native stub.
        # Never start from this helper's transient command-substitution parents.
        if ($MsysAncestry -notmatch '^[1-9][0-9]*(,[1-9][0-9]*){0,15}$') { exit 2 }
        $msysPids = @($MsysAncestry.Split(',') | ForEach-Object { [uint32]$_ })
        if ($ProcessId -ne $msysPids[0]) { exit 2 }
        $msysParents = @{}
        for ($i = 0; $i -lt $msysPids.Count - 1; $i++) {
            $msysParents[$msysPids[$i]] = $msysPids[$i + 1]
        }
        $table = @{}
        Get-CimInstance Win32_Process -OperationTimeoutSec 3 | ForEach-Object {
            $table[[uint32]$_.ProcessId] = $_
        }
        $current = $ProcessId
        $child = $null
        $seen = @{}
        $rows = @()
        for ($hop = 0; $hop -lt 16 -and $current -gt 0; $hop++) {
            if ($seen.ContainsKey($current)) { throw 'Cyclic process ancestry' }
            $seen[$current] = $true
            $process = $table[$current]
            if (!$process) { break }
            # A parent PID may have been recycled since the child was born.
            # Such a process is not its parent, even if it is another agent.
            if (!$process.CreationDate) { throw 'Missing process creation time' }
            if ($child -and $process.CreationDate -gt $child.CreationDate) { break }
            $rows += Process-Row $process
            $child = $process
            if ($msysParents.ContainsKey($current)) {
                $current = $msysParents[$current]
            } else {
                $current = [uint32]$process.ParentProcessId
            }
        }
        $rows
    }
    exit 0
} catch {
    [Console]::Error.WriteLine('Windows session process query failed: ' + $_.Exception.Message)
    exit 2
}
