[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ReleaseDigest
)

$ErrorActionPreference = 'Stop'
$env:WSL_UTF8 = '1'
$taskName = 'MyunaServer-Start-Server-Ubuntu'
$releaseRoot = Join-Path $env:ProgramFiles "MyunaServer\HostColdBoot\releases\$ReleaseDigest"
$manifestPath = Join-Path $releaseRoot 'MANIFEST.json'
$launcher = Join-Path $releaseRoot 'Start-MyunaHostColdBoot.vbs'
$powerShellScript = Join-Path $releaseRoot 'Start-MyunaHostColdBoot.ps1'
$statePath = 'C:\ProgramData\MyunaServer\State\host-cold-boot-v1.json'
$linuxRelease = "/opt/myuna/host-cold-boot/releases/$ReleaseDigest"
$linuxInstaller = "$linuxRelease/install_host_cold_boot_release_v1.py"
$linuxReadiness = "$linuxRelease/host_cold_boot_readiness_v1.py"
$wscript = "$env:WINDIR\System32\wscript.exe"
$wsl = "$env:WINDIR\System32\wsl.exe"
$windowsPowerShell = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"

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

try {
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ReleaseDigest) {
        throw 'WINDOWS_RELEASE_REJECTED'
    }

    $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\'
    $expectedArguments = "//B //NoLogo `"$launcher`" `"$powerShellScript`" `"$linuxReadiness`""
    $lockAfterReady = $task.Actions[0].Arguments -eq ($expectedArguments + ' --lock-after-ready')
    if ($task.State.ToString() -ne 'Running' -or
        $task.Actions.Count -ne 1 -or
        $task.Actions[0].Execute -ne $wscript -or
        ($task.Actions[0].Arguments -ne $expectedArguments -and -not $lockAfterReady) -or
        $task.Triggers.Count -ne 1 -or
        $task.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskLogonTrigger' -or
        $task.Principal.LogonType.ToString() -ne 'Interactive' -or
        $task.Principal.RunLevel.ToString() -ne 'Limited' -or
        [int]$task.Settings.RestartCount -ne 12) {
        throw 'TASK_STATE_REJECTED'
    }

    $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
    $stateFile = Get-Item -LiteralPath $statePath
    $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    $stateBootTime = [DateTimeOffset]::Parse($state.windows_boot_time).UtcDateTime
    if ($stateFile.LastWriteTimeUtc -lt $bootTime -or
        [Math]::Abs(($stateBootTime - $bootTime).TotalSeconds) -gt 2 -or
        $state.schema -ne 'myuna.host-cold-boot-readiness.v1' -or
        $state.status -ne 'HOST_COLD_BOOT_READY_NO_AUDIT' -or
        $state.release -ne $ReleaseDigest -or
        $state.windows_network -ne 'up-with-default-route' -or
        $state.windows_cc_switch -ne 'running-with-run-entry' -or
        $state.windows_pandafan -ne 'connected-and-tun-up' -or
        $state.windows_chatgpt -ne 'window-and-codex-ready' -or
        $state.lock_after_ready -ne $lockAfterReady -or
        $state.core_http_health_called -ne $false -or
        $state.message_model_memory_tool_calls -ne $false -or
        $state.real_e2e -ne $false) {
        throw 'CURRENT_BOOT_RECEIPT_REJECTED'
    }

    $ccSwitchTarget = Join-Path $env:LOCALAPPDATA 'Programs\CC Switch\cc-switch.exe'
    $ccSwitchRunCommand = Get-ItemPropertyValue `
        -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' `
        -Name 'CC Switch' `
        -ErrorAction SilentlyContinue
    $normalizedRunTarget = ([string]$ccSwitchRunCommand).Trim().Trim('"')
    $ccSwitchRunReady = $normalizedRunTarget -eq $ccSwitchTarget -and
        (Test-Path -LiteralPath $ccSwitchTarget -PathType Leaf)
    $physicalAdapters = @(
        Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true }
    )
    $defaultRoutes = @(
        Get-NetRoute `
            -AddressFamily IPv4 `
            -DestinationPrefix '0.0.0.0/0' `
            -PolicyStore ActiveStore `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -ne '0.0.0.0' }
    )
    $networkReady = $false
    foreach ($adapter in $physicalAdapters) {
        if ($defaultRoutes.InterfaceIndex -contains $adapter.InterfaceIndex) {
            $networkReady = $true
            break
        }
    }
    $ccSwitch = @(
        Get-Process -Name 'cc-switch' -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -eq $ccSwitchTarget }
    )
    if (-not $networkReady -or -not $ccSwitchRunReady -or $ccSwitch.Count -eq 0) {
        throw 'WINDOWS_PREREQUISITES_REJECTED'
    }

    $pandaFanLauncher = Join-Path $releaseRoot 'Start-PandaFanAutoconnect.ps1'
    $pandaFanArguments = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$pandaFanLauncher`""
    $pandaFanTask = Get-ScheduledTask -TaskName 'PandaFan Elevated AutoStart' -ErrorAction Stop
    if ($pandaFanTask.Actions.Count -ne 1 -or
        $pandaFanTask.Actions[0].Execute -ne $windowsPowerShell -or
        $pandaFanTask.Actions[0].Arguments -ne $pandaFanArguments -or
        $pandaFanTask.Settings.Enabled -ne $true -or
        $pandaFanTask.Principal.LogonType.ToString() -ne 'Interactive' -or
        $pandaFanTask.Principal.RunLevel.ToString() -ne 'Highest' -or
        @($pandaFanTask.Triggers | Where-Object {
            $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger'
        }).Count -ne 1) {
        throw 'PANDAFAN_STARTUP_REJECTED'
    }
    $pandaFanConfigPath = Join-Path $env:APPDATA 'PandaFan\config.json'
    $pandaFanConfigFile = Get-Item -LiteralPath $pandaFanConfigPath -ErrorAction Stop
    $pandaFanConfig = [System.IO.File]::ReadAllText(
        $pandaFanConfigPath,
        [System.Text.Encoding]::UTF8
    ) | ConvertFrom-Json -ErrorAction Stop
    if ($pandaFanConfig.runTimeState.auto_connect_on_start -ne $true -or
        $pandaFanConfig.user_disconnected -ne $false -or
        $null -eq $pandaFanConfig.last_connect_line -or
        [string]$pandaFanConfig.runTimeState.connect_state.status -ne 'connected' -or
        $pandaFanConfigFile.LastWriteTimeUtc -lt $bootTime) {
        throw 'PANDAFAN_CONNECTION_REJECTED'
    }
    $pandaFanRuntime = Invoke-RestMethod `
        -Uri 'http://127.0.0.1:10079/configs' `
        -TimeoutSec 2 `
        -ErrorAction Stop
    $pandaFanAdapter = Get-NetAdapter `
        -Name ([string]$pandaFanRuntime.tun.device) `
        -ErrorAction SilentlyContinue
    if (-not [bool]$pandaFanRuntime.tun.enable -or
        $null -eq $pandaFanAdapter -or
        $pandaFanAdapter.Status -ne 'Up') {
        throw 'PANDAFAN_TUN_REJECTED'
    }

    $chatGptShortcut = Join-Path ([Environment]::GetFolderPath('Startup')) 'ChatGPT.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($chatGptShortcut)
    $chatGptWindowReady = @(
        Get-Process -Name 'ChatGPT' -ErrorAction SilentlyContinue |
            Where-Object { $_.MainWindowHandle -ne 0 }
    ).Count -gt 0
    if ([IO.Path]::GetFileName($shortcut.TargetPath) -ne 'explorer.exe' -or
        $shortcut.Arguments -notlike 'shell:AppsFolder\*' -or
        -not $chatGptWindowReady -or
        $null -eq (Get-Process -Name 'codex' -ErrorAction SilentlyContinue)) {
        throw 'CHATGPT_CODEX_STARTUP_REJECTED'
    }

    $linuxVerifyProbe = Invoke-WslNative -ArgumentList @('-d', 'Server-Ubuntu', '-u', 'root', '--', '/usr/bin/python3', $linuxInstaller, '--verify-only', $linuxRelease, $ReleaseDigest)
    if ($linuxVerifyProbe.ExitCode -ne 0) {
        throw 'LINUX_RELEASE_REJECTED'
    }
    $linuxVerify = ($linuxVerifyProbe.Output -join "`n") | ConvertFrom-Json -ErrorAction Stop
    if ($linuxVerify.status -ne 'RELEASE_VERIFIED_NO_MUTATION' -or $linuxVerify.release -ne $ReleaseDigest) {
        throw 'LINUX_RELEASE_RECEIPT_REJECTED'
    }

    $linuxReadinessProbe = Invoke-WslNative -ArgumentList @('-d', 'Server-Ubuntu', '-u', 'root', '--', '/usr/bin/python3', $linuxReadiness)
    if ($linuxReadinessProbe.ExitCode -ne 0) {
        throw 'LINUX_READINESS_REJECTED'
    }
    $linux = ($linuxReadinessProbe.Output -join "`n") | ConvertFrom-Json -ErrorAction Stop
    if ($linux.schema -ne 'myuna.host-cold-boot-readiness.v1' -or
        $linux.status -ne 'HOST_COLD_BOOT_READY_NO_AUDIT' -or
        $linux.ready -ne $true -or
        $linux.core_http_health_called -ne $false -or
        $linux.message_model_memory_tool_calls -ne $false -or
        $linux.real_e2e -ne $false) {
        throw 'LINUX_READINESS_RECEIPT_REJECTED'
    }

    [pscustomobject][ordered]@{
        schema = 'myuna.host-cold-boot-postboot-verification.v1'
        status = 'CURRENT_BOOT_READY_NO_AUDIT'
        release = $ReleaseDigest
        boot_time = $bootTime.ToString('o')
        task = 'running'
        windows_network = 'up-with-default-route'
        windows_cc_switch = 'running-with-run-entry'
        windows_pandafan = 'connected-and-tun-up'
        windows_chatgpt = 'window-and-codex-ready'
        lock_after_ready = $lockAfterReady
        linux_release = 'verified'
        linux_readiness = 'ready'
        systemd = $linux.systemd
        archive_count = $linux.archive_count
        core_http_health_called = $false
        message_model_memory_tool_calls = $false
        real_e2e = $false
    } | ConvertTo-Json -Compress
    exit 0
}
catch {
    [pscustomobject][ordered]@{
        schema = 'myuna.host-cold-boot-postboot-verification.v1'
        status = 'CURRENT_BOOT_NOT_READY'
        release = $ReleaseDigest
        failure_class = $(if ($_.Exception.Message -match '^[A-Z0-9_]+$') { $_.Exception.Message } else { 'INSPECTION_ERROR' })
        core_http_health_called = $false
        message_model_memory_tool_calls = $false
        real_e2e = $false
    } | ConvertTo-Json -Compress
    exit 1
}
