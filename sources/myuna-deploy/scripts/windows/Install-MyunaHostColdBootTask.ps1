[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ReleaseDigest,
    [switch]$StartNow,
    [switch]$LockAfterReady
)

$ErrorActionPreference = 'Stop'
$taskName = 'MyunaServer-Start-Server-Ubuntu'
$releaseRoot = Join-Path $env:ProgramFiles "MyunaServer\HostColdBoot\releases\$ReleaseDigest"
$powerShellScript = Join-Path $releaseRoot 'Start-MyunaHostColdBoot.ps1'
$launcher = Join-Path $releaseRoot 'Start-MyunaHostColdBoot.vbs'
$pandaFanLauncher = Join-Path $releaseRoot 'Start-PandaFanAutoconnect.ps1'
$linuxReadiness = "/opt/myuna/host-cold-boot/releases/$ReleaseDigest/host_cold_boot_readiness_v1.py"
$wscript = "$env:WINDIR\System32\wscript.exe"
$wsl = "$env:WINDIR\System32\wsl.exe"
$windowsPowerShell = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$pandaFanTaskName = 'PandaFan Elevated AutoStart'
$backupRoot = 'C:\ProgramData\MyunaServer\Backups\HostColdBoot'
$backup = Join-Path $backupRoot ((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + $ReleaseDigest.Substring(0, 12) + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$statePath = 'C:\ProgramData\MyunaServer\State\host-cold-boot-v1.json'
$oldTaskWasRunning = $false
$oldPandaFanTaskWasRunning = $false
$oldStateExisted = Test-Path -LiteralPath $statePath -PathType Leaf
$registeredNewTask = $false
$registeredNewPandaFanTask = $false

function Invoke-WslNative {
    param([Parameter(Mandatory)][string[]]$ArgumentList)

    if (-not (Test-Path -LiteralPath $wsl -PathType Leaf)) {
        throw 'WSL_EXECUTABLE_REJECTED'
    }
    $previousErrorActionPreference = $ErrorActionPreference
    $nativeExitCode = $null
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $wsl @ArgumentList 2>$null)
        $nativeExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($null -eq $nativeExitCode) {
        $nativeExitCode = -1
    }
    [pscustomobject]@{
        Output = $output
        ExitCode = $nativeExitCode
    }
}

foreach ($path in @($powerShellScript, $launcher, $pandaFanLauncher)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'WINDOWS_RELEASE_REJECTED'
    }
}

$linuxReleaseProbe = Invoke-WslNative -ArgumentList @('-d', 'Server-Ubuntu', '-u', 'root', '--', '/usr/bin/test', '-f', $linuxReadiness)
if ($linuxReleaseProbe.ExitCode -ne 0) {
    throw 'LINUX_RELEASE_REJECTED'
}

New-Item -ItemType Directory -Force -Path $backup | Out-Null
$existing = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    $oldTaskWasRunning = $existing.State -eq 'Running'
    Export-ScheduledTask -TaskName $taskName -TaskPath '\' | Set-Content -LiteralPath (Join-Path $backup 'task.xml') -Encoding Unicode
}
$existingPandaFanTask = Get-ScheduledTask `
    -TaskName $pandaFanTaskName `
    -TaskPath '\' `
    -ErrorAction SilentlyContinue
if ($null -eq $existingPandaFanTask) {
    throw 'PANDAFAN_TASK_PRESTATE_REJECTED'
}
$oldPandaFanTaskWasRunning = $existingPandaFanTask.State -eq 'Running'
Export-ScheduledTask -TaskName $pandaFanTaskName -TaskPath '\' |
    Set-Content -LiteralPath (Join-Path $backup 'pandafan-task.xml') -Encoding Unicode
if ($oldStateExisted) {
    Copy-Item -LiteralPath $statePath -Destination (Join-Path $backup 'state.json')
}

$arguments = "//B //NoLogo `"$launcher`" `"$powerShellScript`" `"$linuxReadiness`"" + $(if ($LockAfterReady) { ' --lock-after-ready' } else { '' })
$action = New-ScheduledTaskAction -Execute $wscript -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 12 `
    -RestartInterval ([TimeSpan]::FromMinutes(1))
$pandaFanArguments = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$pandaFanLauncher`""
$pandaFanAction = New-ScheduledTaskAction `
    -Execute $windowsPowerShell `
    -Argument $pandaFanArguments
$pandaFanTrigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
$pandaFanTrigger.Delay = 'PT30S'
$pandaFanPrincipal = New-ScheduledTaskPrincipal `
    -UserId $currentUser `
    -LogonType Interactive `
    -RunLevel Highest
$pandaFanSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

try {
    if ($StartNow -and $oldTaskWasRunning) {
        Stop-ScheduledTask -TaskName $taskName -TaskPath '\'
    }
    if ($StartNow) {
        Stop-ScheduledTask -TaskName $pandaFanTaskName -TaskPath '\' -ErrorAction SilentlyContinue
        Get-Process -Name 'PandaFan', 'clash' -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Register-ScheduledTask `
        -TaskName $pandaFanTaskName `
        -Action $pandaFanAction `
        -Trigger $pandaFanTrigger `
        -Principal $pandaFanPrincipal `
        -Settings $pandaFanSettings `
        -Description 'Content-addressed elevated PandaFan launch with bounded built-in autoconnect recovery.' `
        -Force | Out-Null
    $registeredNewPandaFanTask = $true

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description 'Content-addressed Myuna host cold-boot keepalive and no-audit readiness controller.' `
        -Force | Out-Null
    $registeredNewTask = $true

    $pandaFanTask = Get-ScheduledTask -TaskName $pandaFanTaskName -TaskPath '\'
    if ($pandaFanTask.Actions.Count -ne 1 -or
        $pandaFanTask.Actions[0].Execute -ne $windowsPowerShell -or
        $pandaFanTask.Actions[0].Arguments -ne $pandaFanArguments -or
        @($pandaFanTask.Triggers | Where-Object {
            $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger'
        }).Count -ne 1 -or
        $pandaFanTask.Principal.LogonType.ToString() -ne 'Interactive' -or
        $pandaFanTask.Principal.RunLevel.ToString() -ne 'Highest') {
        throw 'PANDAFAN_TASK_POSTSTATE_REJECTED'
    }

    $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\'
    if ($task.Actions.Count -ne 1 -or
        $task.Actions[0].Execute -ne $wscript -or
        $task.Actions[0].Arguments -ne $arguments -or
        $task.Triggers.Count -ne 1 -or
        $task.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskLogonTrigger' -or
        $task.Principal.LogonType.ToString() -ne 'Interactive' -or
        $task.Principal.RunLevel.ToString() -ne 'Limited' -or
        [int]$task.Settings.RestartCount -ne 12) {
        throw 'TASK_POSTSTATE_REJECTED'
    }

    if ($StartNow) {
        $startedAt = [datetime]::UtcNow
        $currentBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
        Start-ScheduledTask -TaskName $pandaFanTaskName -TaskPath '\'
        Start-ScheduledTask -TaskName $taskName -TaskPath '\'
        $deadline = (Get-Date).AddSeconds(420)
        $ready = $false
        do {
            Start-Sleep -Seconds 3
            if (Test-Path -LiteralPath $statePath -PathType Leaf) {
                $stateFile = Get-Item -LiteralPath $statePath
                if ($stateFile.LastWriteTimeUtc -ge $startedAt) {
                    try {
                        $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
                        $stateBootTime = [DateTimeOffset]::Parse($state.windows_boot_time).UtcDateTime
                        $currentTaskState = (Get-ScheduledTask -TaskName $taskName -TaskPath '\').State.ToString()
                        $ready = $state.release -eq $ReleaseDigest -and
                            $state.status -eq 'HOST_COLD_BOOT_READY_NO_AUDIT' -and
                            $state.windows_network -eq 'up-with-default-route' -and
                            $state.windows_cc_switch -eq 'running-with-run-entry' -and
                            $state.windows_pandafan -eq 'connected-and-tun-up' -and
                            $state.windows_chatgpt -eq 'window-and-codex-ready' -and
                            $state.lock_after_ready -eq [bool]$LockAfterReady -and
                            [Math]::Abs(($stateBootTime - $currentBootTime).TotalSeconds) -le 2 -and
                            $currentTaskState -eq 'Running' -and
                            $state.core_http_health_called -eq $false -and
                            $state.real_e2e -eq $false
                    }
                    catch {
                        $ready = $false
                    }
                }
            }
        } while (-not $ready -and (Get-Date) -lt $deadline)
        if (-not $ready) {
            throw 'TASK_READINESS_TIMEOUT'
        }
    }

    $payload = [ordered]@{
        schema = 'myuna.host-cold-boot-task-install.v1'
        status = $(if ($StartNow) { 'INSTALLED_READY_NO_AUDIT' } else { 'INSTALLED_INACTIVE' })
        task = $taskName
        pandafan_task = $pandaFanTaskName
        release = $ReleaseDigest
        trigger = $task.Triggers[0].CimClass.CimClassName
        logon_type = $task.Principal.LogonType.ToString()
        run_level = $task.Principal.RunLevel.ToString()
        restart_count = $task.Settings.RestartCount
        restart_interval = $task.Settings.RestartInterval
        backup = $backup
        started = [bool]$StartNow
        lock_after_ready = [bool]$LockAfterReady
        autologon_changed = $false
        real_e2e = $false
        core_http_health_called = $false
    }
    [pscustomobject]$payload | ConvertTo-Json -Compress
}
catch {
    if ($registeredNewTask) {
        Stop-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($registeredNewPandaFanTask) {
        Stop-ScheduledTask -TaskName $pandaFanTaskName -TaskPath '\' -ErrorAction SilentlyContinue
        Get-Process -Name 'PandaFan', 'clash' -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask `
            -TaskName $pandaFanTaskName `
            -TaskPath '\' `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    $taskBackup = Join-Path $backup 'task.xml'
    if (Test-Path -LiteralPath $taskBackup -PathType Leaf) {
        $xml = Get-Content -LiteralPath $taskBackup -Raw -Encoding Unicode
        Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Xml $xml -Force | Out-Null
    }
    $pandaFanTaskBackup = Join-Path $backup 'pandafan-task.xml'
    if (Test-Path -LiteralPath $pandaFanTaskBackup -PathType Leaf) {
        $pandaFanXml = Get-Content `
            -LiteralPath $pandaFanTaskBackup `
            -Raw `
            -Encoding Unicode
        Register-ScheduledTask `
            -TaskName $pandaFanTaskName `
            -TaskPath '\' `
            -Xml $pandaFanXml `
            -Force | Out-Null
        if ($oldPandaFanTaskWasRunning -or $StartNow) {
            Start-ScheduledTask -TaskName $pandaFanTaskName -TaskPath '\'
        }
    }
    if ($oldTaskWasRunning -and
        (Test-Path -LiteralPath $taskBackup -PathType Leaf)) {
        Start-ScheduledTask -TaskName $taskName -TaskPath '\'
    }
    $stateBackup = Join-Path $backup 'state.json'
    if (Test-Path -LiteralPath $stateBackup -PathType Leaf) {
        Copy-Item -LiteralPath $stateBackup -Destination $statePath -Force
    }
    elseif (-not $oldStateExisted) {
        Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    }
    throw 'TASK_INSTALL_ROLLED_BACK'
}
