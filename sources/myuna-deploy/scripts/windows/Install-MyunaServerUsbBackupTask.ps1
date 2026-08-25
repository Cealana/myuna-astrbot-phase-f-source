[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$taskName = 'MyunaServer-Daily-USB-Backup'
$scriptPath = 'C:\Server-Control\Backup-MyunaServerToUsb.ps1'
$powerShell = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name

if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
    throw "Missing backup launcher: $scriptPath"
}

$action = New-ScheduledTaskAction -Execute $powerShell -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -Daily -At '05:30'
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::FromHours(2))

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Daily encrypted Myuna server backup to the identity-bound Server BU USB drive.' -Force | Out-Null
$task = Get-ScheduledTask -TaskName $taskName
$info = Get-ScheduledTaskInfo -TaskName $taskName
[pscustomobject]@{
    TaskName = $task.TaskName
    State = $task.State.ToString()
    UserId = $task.Principal.UserId
    RunLevel = $task.Principal.RunLevel.ToString()
    NextRunTime = $info.NextRunTime
    Action = "$($task.Actions.Execute) $($task.Actions.Arguments)"
} | ConvertTo-Json -Depth 3
