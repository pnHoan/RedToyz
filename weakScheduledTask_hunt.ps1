<#
.SYNOPSIS
    Audits scheduled tasks running under high-privilege accounts for common
    exploitation vectors: unquoted paths, writable directories, and optionally
    exports findings to CSV.

.DESCRIPTION
    Enumerates all scheduled tasks and filters those running under any
    high-privilege account. Privilege is determined by:
      (1) Built-in accounts  - SYSTEM, NT AUTHORITY\*, NETWORK SERVICE
      (2) Local admin group  - any account that is a member of the local
          Administrators group at runtime, including custom admin accounts
          (e.g. corp-admin, svc-deploy, domain admins)
      (3) RunLevel = Highest - tasks explicitly requesting elevation regardless
          of which account they run under

    For each matched task, the script checks:
      - Whether the executable path is unquoted and contains spaces
      - Whether the executable's parent directory is writable by low-priv users
      - What trigger type(s) are configured (e.g. Daily, AtLogon, AtStartup)

    Use -IgnoreDefaults to suppress noise from built-in Windows tasks. This
    applies two filters simultaneously:
      (1) Task path filter  - skips tasks under \Microsoft\, \Windows\, etc.
      (2) Executable filter - skips tasks whose binary resolves to a trusted
          Windows system directory (System32, SysWOW64, WinSxS, etc.)

    A task action is only excluded when BOTH filters agree it looks like a
    Windows default, reducing false negatives from third-party tasks that
    happen to call a system binary.

.PARAMETER ExportCsv
    Path to a CSV file to export results to. If omitted, results are printed
    to the terminal.

.PARAMETER IgnoreDefaults
    Skips tasks whose scheduler path matches a built-in Windows folder prefix
    AND whose executable resolves to a trusted Windows system directory.

.EXAMPLE
    .\weakScheduledTaskHunt.ps1
    Prints all privileged task findings to the terminal.

.EXAMPLE
    .\weakScheduledTaskHunt.ps1 -IgnoreDefaults
    Excludes built-in Windows tasks; focuses on third-party and custom tasks.

.EXAMPLE
    .\weakScheduledTaskHunt.ps1 -IgnoreDefaults -ExportCsv "C:\audit\priv_tasks.csv"
    Excludes built-in Windows tasks and exports findings to CSV.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [switch]$IgnoreDefaults
)

# ---------------------------------------------------------------------------
# Filter 1 - Task scheduler folder prefixes for built-in Windows tasks.
# These are Task Scheduler paths, not file system paths.
# ---------------------------------------------------------------------------
$DefaultTaskPaths = @(
    '\Microsoft\',
    '\Windows\',
    '\MicrosoftAntimalware\'
)

# ---------------------------------------------------------------------------
# Filter 2 - Trusted Windows executable directories.
# Resolved at runtime so they adapt to non-default Windows install drives.
# Any task whose binary starts with one of these prefixes is treated as a
# legitimate Windows component and suppressed under -IgnoreDefaults.
# ---------------------------------------------------------------------------
$sysRoot     = [System.Environment]::GetEnvironmentVariable('SystemRoot')
$progFiles   = [System.Environment]::GetEnvironmentVariable('ProgramFiles')
$progFiles86 = [System.Environment]::GetEnvironmentVariable('ProgramFiles(x86)')

$TrustedExePaths = @(
    # Core OS binary directories
    "$sysRoot\System32\",
    "$sysRoot\SysWOW64\",
    "$sysRoot\SysNative\",
    "$sysRoot\WinSxS\",
    "$sysRoot\servicing\",

    # Windows runtime and framework directories
    "$sysRoot\Microsoft.NET\",
    "$sysRoot\assembly\",

    # PowerShell shipped with Windows
    "$sysRoot\System32\WindowsPowerShell\",

    # WMI infrastructure
    "$sysRoot\System32\wbem\",

    # Windows Update and store infrastructure
    "$sysRoot\SoftwareDistribution\",
    "$sysRoot\System32\DriverStore\",

    # Built-in security, management, and media tooling (64-bit)
    "$progFiles\Windows Defender\",
    "$progFiles\Windows Defender Advanced Threat Protection\",
    "$progFiles\WindowsPowerShell\",
    "$progFiles\Windows Media Player\",
    "$progFiles\Windows NT\",
    "$progFiles\Common Files\Microsoft Shared\",

    # Built-in security, management, and media tooling (32-bit on 64-bit OS)
    "$progFiles86\Windows Defender\",
    "$progFiles86\WindowsPowerShell\",
    "$progFiles86\Common Files\Microsoft Shared\"

) | Where-Object { $_ }    # drop entries where an env var was undefined

#region --- Helpers ---

function Get-TriggerSummary {
    param([object[]]$Triggers)

    if (-not $Triggers -or $Triggers.Count -eq 0) {
        return "None"
    }

    $labels = foreach ($t in $Triggers) {
        $type = $t.GetType().Name
        switch -Wildcard ($type) {
            'MSFT_TaskTimeTrigger'               { "Once"           }
            'MSFT_TaskDailyTrigger'              { "Daily"          }
            'MSFT_TaskWeeklyTrigger'             { "Weekly"         }
            'MSFT_TaskMonthlyTrigger'            { "Monthly"        }
            'MSFT_TaskMonthlyDOWTrigger'         { "Monthly(DOW)"   }
            'MSFT_TaskLogonTrigger'              { "AtLogon"        }
            'MSFT_TaskBootTrigger'               { "AtStartup"      }
            'MSFT_TaskSessionStateChangeTrigger' { "OnSession"      }
            'MSFT_TaskEventTrigger'              { "OnEvent"        }
            'MSFT_TaskIdleTrigger'               { "OnIdle"         }
            'MSFT_TaskRegistrationTrigger'       { "OnRegistration" }
            default                              { $type -replace 'MSFT_Task|Trigger', '' }
        }
    }

    return ($labels | Select-Object -Unique) -join "; "
}

function Test-DirectoryWritable {
    param([string]$DirPath)

    if (-not $DirPath -or -not (Test-Path $DirPath -ErrorAction SilentlyContinue)) {
        return $false
    }

    try {
        $acl = Get-Acl -Path $DirPath -ErrorAction Stop
        $writableEntry = $acl.Access | Where-Object {
            $_.IdentityReference.Value -match 'Users|Everyone|Authenticated Users|BUILTIN\\Users' -and
            $_.FileSystemRights -match 'Write|FullControl|Modify' -and
            $_.AccessControlType -eq 'Allow'
        }
        return [bool]$writableEntry
    }
    catch {
        return $false
    }
}

function Get-LocalAdminAccounts {
    <#
    .SYNOPSIS
        Returns a HashSet of all account identifiers that are members of the
        local Administrators group. Includes the account name in multiple
        normalised forms (DOMAIN\user, user, SID) to maximise match coverage
        against the various formats the Task Scheduler stores in RunAs.
    #>
    $set = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    try {
        $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
        foreach ($m in $members) {
            if ($m.Name) {
                $set.Add($m.Name)         | Out-Null   # COMPUTERNAME\user or DOMAIN\user
                if ($m.Name -match '\\') {
                    $set.Add(($m.Name -split '\\')[1]) | Out-Null   # bare username
                }
            }
            if ($m.SID) {
                $set.Add($m.SID.Value)    | Out-Null   # SID string e.g. S-1-5-21-...
            }
        }
    }
    catch {
        # Fallback for environments where Get-LocalGroupMember is unavailable
        # (e.g. PS 4, Server Core without the module). Parse net.exe output.
        try {
            $output   = & net localgroup Administrators 2>$null
            $inBlock  = $false
            foreach ($line in $output) {
                if ($line -match '^-{5,}')                            { $inBlock = $true;  continue }
                if ($line -match 'The command completed successfully') { $inBlock = $false; continue }
                if ($inBlock -and $line.Trim() -ne '') {
                    $name = $line.Trim()
                    $set.Add($name) | Out-Null
                    if ($name -match '\\') {
                        $set.Add(($name -split '\\')[1]) | Out-Null
                    }
                }
            }
        }
        catch {}
    }

    return $set
}

function Test-IsDefaultWindowsTaskPath {
    param([string]$TaskPath)
    foreach ($prefix in $DefaultTaskPaths) {
        if ($TaskPath -like "$prefix*") { return $true }
    }
    return $false
}

function Test-IsTrustedWindowsExe {
    param([string]$ExePath)
    if (-not $ExePath) { return $false }
    foreach ($trustedDir in $TrustedExePaths) {
        if ($ExePath -like "$trustedDir*") { return $true }
    }
    return $false
}

#endregion

#region --- Main ---

Write-Host ""
Write-Host "weakScheduledTaskHunt.ps1 - Privileged Scheduled Task Audit"
Write-Host "============================================================"

# Enumerate local Administrators group members at runtime
$adminAccounts = Get-LocalAdminAccounts

if ($adminAccounts.Count -gt 0) {
    Write-Host "Admin group members detected ($($adminAccounts.Count) identifiers):"
    # Display unique display names only (skip bare SIDs and duplicates)
    $displayNames = $adminAccounts | Where-Object { $_ -notmatch '^S-1-' } | Sort-Object -Unique
    foreach ($name in $displayNames) {
        Write-Host "  - $name"
    }
}
else {
    Write-Host "Admin group : Could not enumerate local Administrators group (results may be incomplete)"
}
Write-Host ""

if ($IgnoreDefaults) {
    Write-Host "Filter  : Windows default tasks excluded (-IgnoreDefaults)"
    Write-Host "          [1] Task path  : \Microsoft\, \Windows\, \MicrosoftAntimalware\"
    Write-Host "          [2] Executable : System32, SysWOW64, WinSxS, .NET, Defender, ..."
    Write-Host "          Note: a task action is only skipped when BOTH filters match."
}

Write-Host ""

$findings     = [System.Collections.Generic.List[PSCustomObject]]::new()
$skippedCount = 0

$allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue

foreach ($task in $allTasks) {
    $principal = $task.Principal
    $runAs     = $principal.UserId
    $runLevel  = $principal.RunLevel

    # Determine if the task runs under a high-privilege account.
    # PrivilegeSource tracks which condition matched, for reporting.
    $privilegeSources = @()

    # (1) Well-known built-in privileged accounts
    if ($runAs -match 'SYSTEM|NT AUTHORITY|NETWORK SERVICE|LOCAL SERVICE') {
        $privilegeSources += 'BuiltIn'
    }

    # (2) Any member of the local Administrators group (catches custom admin accounts)
    if ($runAs -and $adminAccounts.Count -gt 0) {
        $bareUser = if ($runAs -match '\\') { ($runAs -split '\\')[1] } else { $runAs }
        if ($adminAccounts.Contains($runAs) -or $adminAccounts.Contains($bareUser)) {
            $privilegeSources += 'LocalAdmin'
        }
    }

    # (3) Task explicitly requests highest run level regardless of account
    if ($runLevel -eq 'Highest') {
        $privilegeSources += 'RunLevel=Highest'
    }

    if ($privilegeSources.Count -eq 0) { continue }

    $privilegeSource = $privilegeSources -join ", "

    $isDefaultTaskPath = Test-IsDefaultWindowsTaskPath -TaskPath $task.TaskPath

    $info           = Get-ScheduledTaskInfo -TaskName $task.TaskName `
                          -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
    $triggerSummary = Get-TriggerSummary -Triggers $task.Triggers

    foreach ($action in $task.Actions) {
        $exe  = $action.Execute
        $args = $action.Arguments

        # Expand environment variables before path checks
        if ($exe) {
            try { $exe = [System.Environment]::ExpandEnvironmentVariables($exe) }
            catch {}
        }

        # Skip actions with no executable — nothing to audit
        if (-not $exe) { continue }

        # -IgnoreDefaults: skip only when BOTH task path AND executable are Windows defaults.
        # This preserves third-party tasks that call system binaries (e.g. a vendor task
        # under \Vendor\ that runs cmd.exe) and Windows-path tasks that call non-system
        # binaries (rare, but worth catching).
        if ($IgnoreDefaults) {
            if ($isDefaultTaskPath -and (Test-IsTrustedWindowsExe -ExePath $exe)) {
                $skippedCount++
                continue
            }
        }

        # Check 1: Unquoted path with spaces (binary/DLL hijack vector)
        $unquotedPath = $exe -and $exe -match ' ' -and $exe -notmatch '^"'

        # Check 2: Parent directory writable by low-privilege users
        $writableDir = $false
        if ($exe) {
            $parentDir = Split-Path -Path $exe -Parent -ErrorAction SilentlyContinue
            if ($parentDir) {
                $writableDir = Test-DirectoryWritable -DirPath $parentDir
            }
        }

        $riskFlags   = @()
        if ($unquotedPath) { $riskFlags += "UnquotedPath" }
        if ($writableDir)  { $riskFlags += "WritableDir"  }
        $riskSummary = if ($riskFlags.Count -gt 0) { $riskFlags -join ", " } else { "None" }

        $findings.Add([PSCustomObject]@{
            TaskName        = $task.TaskName
            TaskPath        = $task.TaskPath
            RunAs           = if ($runAs) { $runAs } else { "(not set)" }
            RunLevel        = $runLevel
            PrivilegeSource = $privilegeSource
            State           = $task.State
            Triggers        = $triggerSummary
            Executable      = $exe
            Arguments       = if ($args) { $args } else { "(none)" }
            UnquotedPath    = $unquotedPath
            WritableDir     = $writableDir
            RiskFlags       = $riskSummary
            LastRun         = $info.LastRunTime
            NextRun         = $info.NextRunTime
        })
    }
}

#endregion

#region --- Output ---

if ($IgnoreDefaults -and $skippedCount -gt 0) {
    Write-Host "Skipped : $skippedCount action(s) matched Windows default filters"
    Write-Host ""
}

if ($findings.Count -eq 0) {
    Write-Host "No privileged scheduled tasks found matching the current filters."
    Write-Host ""
    exit 0
}

Write-Host "Tasks found: $($findings.Count)"
Write-Host ""

if ($ExportCsv) {
    try {
        $findings | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host "Results exported to: $ExportCsv"
        Write-Host ""

        # Always print a risk-flagged summary to terminal even when exporting
        Write-Host "Summary (RiskFlags != None):"
        Write-Host "----------------------------"
        $risky = $findings | Where-Object { $_.RiskFlags -ne "None" }
        if ($risky) {
            $risky | Format-Table TaskName, RunAs, PrivilegeSource, Triggers, RiskFlags -AutoSize
        }
        else {
            Write-Host "No tasks with active risk flags detected."
            Write-Host ""
        }
    }
    catch {
        Write-Error "Failed to export CSV: $_"
        exit 1
    }
}
else {
    foreach ($f in $findings) {
        Write-Host "Task        : $($f.TaskName)"
        Write-Host "Path        : $($f.TaskPath)"
        Write-Host "Run As      : $($f.RunAs)"
        Write-Host "Run Level   : $($f.RunLevel)"
        Write-Host "Priv Source : $($f.PrivilegeSource)"
        Write-Host "State       : $($f.State)"
        Write-Host "Triggers    : $($f.Triggers)"
        Write-Host "Executable  : $($f.Executable)"
        Write-Host "Arguments   : $($f.Arguments)"
        Write-Host "Unquoted    : $($f.UnquotedPath)"
        Write-Host "Writable Dir: $($f.WritableDir)"
        Write-Host "Risk Flags  : $($f.RiskFlags)"
        Write-Host "Last Run    : $($f.LastRun)"
        Write-Host "Next Run    : $($f.NextRun)"
        Write-Host "------------------------------------------------------------"
    }
}

#endregion