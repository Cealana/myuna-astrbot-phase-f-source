[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$env:WSL_UTF8 = '1'

$expected = [ordered]@{
    DriveLetter = 'E'
    Label = 'Server BU'
    FileSystem = 'exFAT'
    DiskSerial = 'AA00000000000489'
    DiskSize = [int64]256641603584
    VolumeUniqueId = '\\?\Volume{5638fb9c-87f1-11f1-912f-9e83345522cc}\'
}
$markerPath = 'E:\Myuna-Server-Backup\DEVICE_ID.json'
$logRoot = 'C:\ProgramData\MyunaServer\Logs'
$logPath = Join-Path $logRoot 'usb-backup-v1.log'
$wslScript = '/opt/myuna/usb-backup/releases/f951d10f67ec68e3598041bbd525c61894e7d089ef996b6dfacc3cdf2a44bc98/server_usb_backup_v1.py'
$wslConfig = '/etc/myuna-usb-backup/config-v1.json'

function Write-BackupEvent {
    param([string]$Status, [string]$Reason = '')
    New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
    [pscustomobject]@{
        Time = (Get-Date).ToString('o')
        Status = $Status
        Reason = $Reason
        Drive = $expected.DriveLetter
    } | ConvertTo-Json -Compress | Add-Content -LiteralPath $logPath -Encoding UTF8
}

try {
    $volume = Get-Volume -DriveLetter $expected.DriveLetter -ErrorAction Stop
    $disk = Get-Partition -DriveLetter $expected.DriveLetter -ErrorAction Stop | Get-Disk -ErrorAction Stop
    if ($volume.HealthStatus -ne 'Healthy' -or
        $volume.FileSystemLabel -ne $expected.Label -or
        $volume.FileSystem -ne $expected.FileSystem -or
        $volume.UniqueId -ne $expected.VolumeUniqueId -or
        $disk.SerialNumber.Trim() -ne $expected.DiskSerial -or
        [int64]$disk.Size -ne $expected.DiskSize) {
        throw 'USB_DEVICE_IDENTITY_MISMATCH'
    }
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        throw 'USB_DEVICE_MARKER_MISSING'
    }
    $marker = Get-Content -LiteralPath $markerPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($marker.schema -ne 'myuna.server-backup-device.v1' -or
        $marker.label -ne $expected.Label -or
        $marker.filesystem -ne $expected.FileSystem -or
        $marker.serial -ne $expected.DiskSerial -or
        [int64]$marker.disk_size -ne $expected.DiskSize) {
        throw 'USB_DEVICE_MARKER_MISMATCH'
    }
    & "$env:WINDIR\System32\wsl.exe" -d Server-Ubuntu -u root -- /usr/bin/mkdir -p /mnt/e
    if ($LASTEXITCODE -ne 0) {
        throw 'WSL_USB_MOUNTPOINT_CREATE_FAILED'
    }
    & "$env:WINDIR\System32\wsl.exe" -d Server-Ubuntu -u root -- /usr/bin/mountpoint -q /mnt/e
    if ($LASTEXITCODE -ne 0) {
        & "$env:WINDIR\System32\wsl.exe" -d Server-Ubuntu -u root -- /usr/bin/mount -t drvfs E: /mnt/e
        if ($LASTEXITCODE -ne 0) {
            throw 'WSL_USB_MOUNT_FAILED'
        }
    }
    Write-BackupEvent -Status 'STARTED'
    & "$env:WINDIR\System32\wsl.exe" -d Server-Ubuntu -u root -- /usr/bin/python3 $wslScript --config $wslConfig
    if ($LASTEXITCODE -ne 0) {
        throw "WSL_BACKUP_FAILED_EXIT_$LASTEXITCODE"
    }
    Write-BackupEvent -Status 'SUCCESS'
    exit 0
}
catch {
    Write-BackupEvent -Status 'FAILED' -Reason $_.Exception.Message
    Write-Error $_.Exception.Message
    exit 1
}
