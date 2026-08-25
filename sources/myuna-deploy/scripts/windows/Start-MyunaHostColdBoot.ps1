[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^/opt/myuna/host-cold-boot/releases/[0-9a-f]{64}/host_cold_boot_readiness_v1\.py$')]
    [string]$LinuxReadinessPath,
    [switch]$LockAfterReady
)

$ErrorActionPreference = 'Stop'
$env:WSL_UTF8 = '1'
$distro = 'Server-Ubuntu'
$logRoot = 'C:\ProgramData\MyunaServer\Logs'
$stateRoot = 'C:\ProgramData\MyunaServer\State'
$logPath = Join-Path $logRoot 'host-cold-boot-v1.log'
$statePath = Join-Path $stateRoot 'host-cold-boot-v1.json'
$releaseDigest = [regex]::Match($LinuxReadinessPath, '/([0-9a-f]{64})/host_cold_boot_readiness_v1\.py$').Groups[1].Value
$windowsBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
$script:pandaFanTunEnableRequested = $false
$controllerProcess = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$PID"
$launcherProcess = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($controllerProcess.ParentProcessId)"
$launcherProcessId = $launcherProcess.ProcessId
$launcherCreationDate = $launcherProcess.CreationDate
$expectedLauncherPath = Join-Path $env:ProgramFiles "MyunaServer\HostColdBoot\releases\$releaseDigest\Start-MyunaHostColdBoot.vbs"
if ($launcherProcess.Name -ne 'wscript.exe' -or
    $launcherProcess.CommandLine -notlike "*$expectedLauncherPath*") {
    throw 'CONTROLLER_LAUNCHER_REJECTED'
}

function Write-ColdBootEvent {
    param(
        [Parameter(Mandatory)][string]$Event,
        [int]$ExitCode = 0,
        [hashtable]$Data = @{}
    )
    New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
    $record = [ordered]@{
        Time = (Get-Date).ToString('o')
        Event = $Event
        Distro = $distro
        ExitCode = $ExitCode
    }
    foreach ($key in $Data.Keys) {
        $record[$key] = $Data[$key]
    }
    [pscustomobject]$record | ConvertTo-Json -Compress | Add-Content -LiteralPath $logPath -Encoding UTF8
}

function New-HiddenWslProcess {
    param([Parameter(Mandatory)][string]$Arguments)
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = "$env:WINDIR\System32\wsl.exe"
    $startInfo.Arguments = $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $startInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'WSL_PROCESS_START_REJECTED'
    }
    return $process
}

function Test-ControllerLauncher {
    $currentLauncher = Get-CimInstance `
        -ClassName Win32_Process `
        -Filter "ProcessId=$launcherProcessId" `
        -ErrorAction SilentlyContinue
    return $null -ne $currentLauncher -and
        $currentLauncher.Name -eq 'wscript.exe' -and
        $currentLauncher.CreationDate -eq $launcherCreationDate -and
        $currentLauncher.CommandLine -like "*$expectedLauncherPath*"
}

function Write-AtomicState {
    param([Parameter(Mandatory)][string]$Payload)
    New-Item -ItemType Directory -Force -Path $stateRoot | Out-Null
    $temporary = Join-Path $stateRoot ('.host-cold-boot-v1.' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [System.IO.File]::WriteAllText($temporary, $Payload + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $statePath -Force
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Get-PandaFanApplicationState {
    $configPath = Join-Path $env:APPDATA 'PandaFan\config.json'
    try {
        $configFile = Get-Item -LiteralPath $configPath -ErrorAction Stop
        $config = [System.IO.File]::ReadAllText(
            $configPath,
            [System.Text.Encoding]::UTF8
        ) | ConvertFrom-Json -ErrorAction Stop
        $ready = $config.runTimeState.auto_connect_on_start -eq $true -and
            $config.user_disconnected -eq $false -and
            $null -ne $config.last_connect_line -and
            [string]$config.runTimeState.connect_state.status -eq 'connected' -and
            $configFile.LastWriteTimeUtc -ge (
                [DateTimeOffset]::Parse($windowsBootTime).UtcDateTime
            )
        [pscustomobject]@{
            Ready = $ready
            Inspection = 'ok'
        }
    }
    catch {
        [pscustomobject]@{
            Ready = $false
            Inspection = 'error'
        }
    }
}

function Get-WindowsPrerequisites {
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
    $ccSwitchReady = $ccSwitchRunReady -and $ccSwitch.Count -gt 0

    $pandaFanLauncher = Join-Path `
        $env:ProgramFiles `
        "MyunaServer\HostColdBoot\releases\$releaseDigest\Start-PandaFanAutoconnect.ps1"
    $windowsPowerShell = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $pandaFanArguments = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$pandaFanLauncher`""
    $pandaFanTask = Get-ScheduledTask -TaskName 'PandaFan Elevated AutoStart' -ErrorAction SilentlyContinue
    $pandaFanTaskReady = $null -ne $pandaFanTask -and
        $pandaFanTask.Actions.Count -eq 1 -and
        $pandaFanTask.Actions[0].Execute -eq $windowsPowerShell -and
        $pandaFanTask.Actions[0].Arguments -eq $pandaFanArguments -and
        $pandaFanTask.Settings.Enabled -eq $true -and
        $pandaFanTask.Principal.LogonType.ToString() -eq 'Interactive' -and
        $pandaFanTask.Principal.RunLevel.ToString() -eq 'Highest' -and
        @($pandaFanTask.Triggers | Where-Object {
            $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger'
        }).Count -eq 1
    $pandaFanReady = $false
    if ($pandaFanTaskReady) {
        try {
            $pandaFanApplication = Get-PandaFanApplicationState
            $pandaFanRuntime = Invoke-RestMethod `
                -Uri 'http://127.0.0.1:10079/configs' `
                -TimeoutSec 2 `
                -ErrorAction Stop
            if ($pandaFanApplication.Ready -and
                -not [bool]$pandaFanRuntime.tun.enable -and
                -not $script:pandaFanTunEnableRequested) {
                Invoke-RestMethod `
                    -Uri 'http://127.0.0.1:10079/configs' `
                    -Method Patch `
                    -ContentType 'application/json' `
                    -Body '{"tun":{"enable":true}}' `
                    -TimeoutSec 5 `
                    -ErrorAction Stop | Out-Null
                $script:pandaFanTunEnableRequested = $true
                Write-ColdBootEvent -Event 'pandafan-tun-enable-requested'
            }
            if ($pandaFanApplication.Ready -and
                [bool]$pandaFanRuntime.tun.enable -and
                -not [string]::IsNullOrWhiteSpace([string]$pandaFanRuntime.tun.device)) {
                $pandaFanAdapter = Get-NetAdapter `
                    -Name ([string]$pandaFanRuntime.tun.device) `
                    -ErrorAction SilentlyContinue
                $pandaFanReady = $null -ne $pandaFanAdapter -and $pandaFanAdapter.Status -eq 'Up'
            }
        }
        catch {
            $pandaFanReady = $false
        }
    }

    $chatGptShortcut = Join-Path ([Environment]::GetFolderPath('Startup')) 'ChatGPT.lnk'
    $chatGptStartupReady = $false
    if (Test-Path -LiteralPath $chatGptShortcut -PathType Leaf) {
        try {
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($chatGptShortcut)
            $chatGptStartupReady = [IO.Path]::GetFileName($shortcut.TargetPath) -eq 'explorer.exe' -and
                $shortcut.Arguments -like 'shell:AppsFolder\*'
        }
        catch {
            $chatGptStartupReady = $false
        }
    }
    $chatGptWindowReady = @(
        Get-Process -Name 'ChatGPT' -ErrorAction SilentlyContinue |
            Where-Object { $_.MainWindowHandle -ne 0 }
    ).Count -gt 0
    $codexProcessReady = $null -ne (Get-Process -Name 'codex' -ErrorAction SilentlyContinue)
    $chatGptReady = $chatGptStartupReady -and $chatGptWindowReady -and $codexProcessReady

    [pscustomobject]@{
        ready = $networkReady -and $ccSwitchReady -and $pandaFanReady -and $chatGptReady
        network = $(if ($networkReady) { 'up-with-default-route' } else { 'not-ready' })
        cc_switch = $(if ($ccSwitchReady) { 'running-with-run-entry' } else { 'not-ready' })
        pandafan = $(if ($pandaFanReady) { 'connected-and-tun-up' } else { 'not-ready' })
        chatgpt = $(if ($chatGptReady) { 'window-and-codex-ready' } else { 'not-ready' })
    }
}

$keepAlive = $null
try {
    Write-ColdBootEvent -Event 'starting'
    $keepAlive = New-HiddenWslProcess -Arguments "-d $distro -u root -- /usr/bin/sleep infinity"
    Write-ColdBootEvent -Event 'keepalive-started'

    $readiness = New-HiddenWslProcess -Arguments "-d $distro -u root -- /usr/bin/python3 $LinuxReadinessPath"
    $deadline = (Get-Date).AddSeconds(390)
    $windows = Get-WindowsPrerequisites
    while (-not $readiness.HasExited -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        if (-not (Test-ControllerLauncher)) {
            throw 'CONTROLLER_LAUNCHER_EXITED'
        }
        $windows = Get-WindowsPrerequisites
    }
    if (-not $readiness.HasExited) {
        $readiness.Kill()
        throw 'READINESS_TIMEOUT'
    }
    $readinessOutput = $readiness.StandardOutput.ReadToEnd().Trim()
    $stderrPresent = -not [string]::IsNullOrWhiteSpace($readiness.StandardError.ReadToEnd())
    if ($readiness.ExitCode -ne 0) {
        throw 'READINESS_REJECTED'
    }
    $receipt = $readinessOutput | ConvertFrom-Json -ErrorAction Stop
    if ($receipt.schema -ne 'myuna.host-cold-boot-readiness.v1' -or
        $receipt.status -ne 'HOST_COLD_BOOT_READY_NO_AUDIT' -or
        $receipt.core_http_health_called -ne $false -or
        $receipt.message_model_memory_tool_calls -ne $false -or
        $receipt.real_e2e -ne $false) {
        throw 'READINESS_RECEIPT_REJECTED'
    }
    while (-not $windows.ready -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        if (-not (Test-ControllerLauncher)) {
            throw 'CONTROLLER_LAUNCHER_EXITED'
        }
        $windows = Get-WindowsPrerequisites
    }
    if (-not $windows.ready) {
        throw 'WINDOWS_PREREQUISITES_REJECTED'
    }
    if ($LockAfterReady) {
        $lock = Start-Process `
            -FilePath "$env:WINDIR\System32\rundll32.exe" `
            -ArgumentList 'user32.dll,LockWorkStation' `
            -WindowStyle Hidden `
            -Wait `
            -PassThru
        if ($lock.ExitCode -ne 0) {
            throw 'WORKSTATION_LOCK_REJECTED'
        }
        Write-ColdBootEvent -Event 'workstation-lock-requested'
    }
    $receipt | Add-Member -NotePropertyName windows_network -NotePropertyValue $windows.network
    $receipt | Add-Member -NotePropertyName windows_cc_switch -NotePropertyValue $windows.cc_switch
    $receipt | Add-Member -NotePropertyName windows_pandafan -NotePropertyValue $windows.pandafan
    $receipt | Add-Member -NotePropertyName windows_chatgpt -NotePropertyValue $windows.chatgpt
    $receipt | Add-Member -NotePropertyName windows_boot_time -NotePropertyValue $windowsBootTime
    $receipt | Add-Member -NotePropertyName lock_after_ready -NotePropertyValue ([bool]$LockAfterReady)
    $receipt | Add-Member -NotePropertyName release -NotePropertyValue $releaseDigest
    Write-AtomicState -Payload ($receipt | ConvertTo-Json -Depth 8 -Compress)
    Write-ColdBootEvent -Event 'ready' -Data @{
        ElapsedSeconds = [int]$receipt.elapsed_seconds
        StderrPresent = $stderrPresent
        WindowsNetwork = $receipt.windows_network
        WindowsCcSwitch = $receipt.windows_cc_switch
        WindowsPandaFan = $receipt.windows_pandafan
        WindowsChatGpt = $receipt.windows_chatgpt
        WindowsBootTime = $windowsBootTime
        Release = $releaseDigest
    }

    while (-not $keepAlive.WaitForExit(3000)) {
        if (-not (Test-ControllerLauncher)) {
            $keepAlive.Kill()
            Write-ColdBootEvent -Event 'controller-launcher-exited'
            exit 0
        }
    }
    $exitCode = $keepAlive.ExitCode
    $stderrPresent = -not [string]::IsNullOrWhiteSpace($keepAlive.StandardError.ReadToEnd())
    Write-ColdBootEvent -Event 'keepalive-exited' -ExitCode $exitCode -Data @{
        StderrPresent = $stderrPresent
    }
    exit $(if ($exitCode -eq 0) { 1 } else { $exitCode })
}
catch {
    if ($null -ne $keepAlive -and -not $keepAlive.HasExited) {
        $keepAlive.Kill()
    }
    if ($_.Exception.Message -eq 'CONTROLLER_LAUNCHER_EXITED') {
        Write-ColdBootEvent -Event 'controller-launcher-exited'
        exit 0
    }
    Write-ColdBootEvent -Event 'failed' -ExitCode 1 -Data @{
        FailureClass = $_.Exception.Message
    }
    exit 1
}
