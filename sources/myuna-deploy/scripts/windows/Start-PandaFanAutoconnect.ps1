[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$pandaFanExecutable = Join-Path $env:LOCALAPPDATA 'Programs\PandaFan\PandaFan.exe'
$configPath = Join-Path $env:APPDATA 'PandaFan\config.json'
$logRoot = 'C:\ProgramData\MyunaServer\Logs'
$logPath = Join-Path $logRoot 'host-cold-boot-v1.log'
$releaseDigest = Split-Path -Leaf $PSScriptRoot
$latin1 = [System.Text.Encoding]::GetEncoding(28591)
$mutex = [System.Threading.Mutex]::new($false, 'Local\PandaFanHealthWatchdog-26856')
$mutexAcquired = $false

function Write-PandaFanEvent {
    param(
        [Parameter(Mandatory)][string]$Event,
        [hashtable]$Data = @{}
    )

    New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
    $record = [ordered]@{
        Time = (Get-Date).ToString('o')
        Event = $Event
        Release = $releaseDigest
        ExitCode = 0
    }
    foreach ($key in $Data.Keys) {
        $record[$key] = $Data[$key]
    }
    [pscustomobject]$record |
        ConvertTo-Json -Compress |
        Add-Content -LiteralPath $logPath -Encoding UTF8
}

function Get-PandaFanConnectionState {
    try {
        $config = [System.IO.File]::ReadAllText(
            $configPath,
            [System.Text.Encoding]::UTF8
        ) | ConvertFrom-Json -ErrorAction Stop
        if ($config.runTimeState.auto_connect_on_start -ne $true -or
            $null -eq $config.last_connect_line) {
            return 'configuration-rejected'
        }
        if ($config.user_disconnected -eq $true) {
            return 'user-disconnected'
        }
        if ([string]$config.runTimeState.connect_state.status -eq 'connected') {
            return 'connected'
        }
        return 'disconnected'
    }
    catch {
        return 'inspection-error'
    }
}

function Reset-PandaFanDisconnectIntent {
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw 'PANDAFAN_CONFIG_REJECTED'
    }
    $bytes = [System.IO.File]::ReadAllBytes($configPath)
    $text = $latin1.GetString($bytes)
    $autoConnectMatches = [regex]::Matches(
        $text,
        '"auto_connect_on_start"\s*:\s*true'
    )
    $lastLineMatches = [regex]::Matches(
        $text,
        '"last_connect_line"\s*:\s*\{'
    )
    $disconnectMatches = [regex]::Matches(
        $text,
        '"user_disconnected"\s*:\s*(true|false)'
    )
    if ($autoConnectMatches.Count -ne 1 -or
        $lastLineMatches.Count -ne 1 -or
        $disconnectMatches.Count -ne 1) {
        throw 'PANDAFAN_CONFIG_SHAPE_REJECTED'
    }
    if ($disconnectMatches[0].Groups[1].Value -eq 'false') {
        return
    }

    $updated = [regex]::Replace(
        $text,
        '"user_disconnected"\s*:\s*true',
        '"user_disconnected":false',
        1
    )
    $temporary = Join-Path (
        Split-Path -Parent $configPath
    ) ('.config.' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [System.IO.File]::WriteAllBytes($temporary, $latin1.GetBytes($updated))
        [System.IO.File]::Replace($temporary, $configPath, $null)
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
    if ((Get-PandaFanConnectionState) -eq 'user-disconnected') {
        throw 'PANDAFAN_DISCONNECT_INTENT_RESET_REJECTED'
    }
    Write-PandaFanEvent -Event 'pandafan-disconnect-intent-reset'
}

function Stop-PandaFanProcesses {
    Get-Process -Name 'PandaFan', 'clash' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}

function Start-PandaFanAttempt {
    param([Parameter(Mandatory)][int]$Attempt)

    Reset-PandaFanDisconnectIntent
    Write-PandaFanEvent -Event 'pandafan-autoconnect-attempt-started' -Data @{
        Attempt = $Attempt
    }
    $attemptStartedAt = [datetime]::UtcNow
    $process = Start-Process `
        -FilePath $pandaFanExecutable `
        -WorkingDirectory (Split-Path -Parent $pandaFanExecutable) `
        -PassThru
    $deadline = (Get-Date).AddSeconds(90)
    do {
        Start-Sleep -Seconds 3
        $configLastWrite = (Get-Item -LiteralPath $configPath).LastWriteTimeUtc
        if ((Get-PandaFanConnectionState) -eq 'connected' -and
            $configLastWrite -ge $attemptStartedAt) {
            Write-PandaFanEvent -Event 'pandafan-autoconnect-connected' -Data @{
                Attempt = $Attempt
            }
            return $process
        }
    } while (-not $process.HasExited -and (Get-Date) -lt $deadline)
    return $null
}

if (-not (Test-Path -LiteralPath $pandaFanExecutable -PathType Leaf)) {
    throw 'PANDAFAN_EXECUTABLE_REJECTED'
}

try {
    try {
        $mutexAcquired = $mutex.WaitOne(0)
    }
    catch [System.Threading.AbandonedMutexException] {
        $mutexAcquired = $true
    }
    if (-not $mutexAcquired) {
        Write-PandaFanEvent -Event 'pandafan-autoconnect-watchdog-owned'
        Reset-PandaFanDisconnectIntent
        $running = Start-Process `
            -FilePath $pandaFanExecutable `
            -WorkingDirectory (Split-Path -Parent $pandaFanExecutable) `
            -PassThru
        $running.WaitForExit()
        exit $running.ExitCode
    }

    $running = $null
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $running = Start-PandaFanAttempt -Attempt $attempt
        if ($null -ne $running) {
            break
        }
        Write-PandaFanEvent -Event 'pandafan-autoconnect-attempt-failed' -Data @{
            Attempt = $attempt
        }
        Stop-PandaFanProcesses
    }
    if ($null -eq $running) {
        Write-PandaFanEvent -Event 'pandafan-autoconnect-failed'
        $running = Start-Process `
            -FilePath $pandaFanExecutable `
            -WorkingDirectory (Split-Path -Parent $pandaFanExecutable) `
            -PassThru
    }
}
catch {
    try {
        Write-PandaFanEvent -Event 'pandafan-autoconnect-preparation-rejected' -Data @{
            FailureClass = $(if ($_.Exception.Message -match '^[A-Z0-9_]+$') {
                $_.Exception.Message
            } else {
                'INSPECTION_ERROR'
            })
        }
    }
    catch {
    }
    $running = Get-Process -Name 'PandaFan' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $running) {
        $running = Start-Process `
            -FilePath $pandaFanExecutable `
            -WorkingDirectory (Split-Path -Parent $pandaFanExecutable) `
            -PassThru
    }
}
finally {
    if ($mutexAcquired) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}

$running.WaitForExit()
exit $running.ExitCode
