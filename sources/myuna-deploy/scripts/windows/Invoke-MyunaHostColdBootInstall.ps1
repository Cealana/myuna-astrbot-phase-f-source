[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ReleaseDigest,
    [Parameter(Mandatory)]
    [string]$StagedRelease,
    [switch]$StartNow,
    [switch]$LockAfterReady
)

$ErrorActionPreference = 'Stop'
$stateRoot = 'C:\ProgramData\MyunaServer\State'
$receiptPath = Join-Path $stateRoot 'host-cold-boot-install-v1.json'
$receiptBackupRoot = 'C:\ProgramData\MyunaServer\Backups\HostColdBoot\install-receipts'
$installer = Join-Path $StagedRelease 'Install-MyunaHostColdBootRelease.ps1'
$script:previousReceiptPreserved = $false

function Preserve-PreviousInstallReceipt {
    if ($script:previousReceiptPreserved -or
        -not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
        $script:previousReceiptPreserved = $true
        return
    }

    New-Item -ItemType Directory -Force -Path $receiptBackupRoot | Out-Null
    $backupName = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') +
        '-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.json'
    Copy-Item -LiteralPath $receiptPath -Destination (Join-Path $receiptBackupRoot $backupName)
    $script:previousReceiptPreserved = $true
}

function Write-AtomicInstallReceipt {
    param([Parameter(Mandatory)][string]$Payload)

    New-Item -ItemType Directory -Force -Path $stateRoot | Out-Null
    Preserve-PreviousInstallReceipt
    $temporary = Join-Path $stateRoot ('.host-cold-boot-install.' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText(
            $temporary,
            $Payload + [Environment]::NewLine,
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporary -Destination $receiptPath -Force
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

try {
    if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
        throw 'RELEASE_INSTALLER_REJECTED'
    }
    $arguments = @{
        ReleaseDigest = $ReleaseDigest
        StagedRelease = $StagedRelease
        StartNow = $StartNow
        LockAfterReady = $LockAfterReady
    }
    $output = & $installer @arguments
    $receipt = $output | ConvertFrom-Json -ErrorAction Stop
    if ($receipt.schema -ne 'myuna.host-cold-boot-release-install.v1' -or
        $receipt.status -notin @('INSTALLED_INACTIVE', 'INSTALLED_READY_NO_AUDIT') -or
        $receipt.release -ne $ReleaseDigest -or
        $receipt.lock_after_ready -ne [bool]$LockAfterReady -or
        $receipt.autologon_changed -ne $false -or
        $receipt.reboot_performed -ne $false -or
        $receipt.wsl_terminated -ne $false -or
        $receipt.real_e2e -ne $false -or
        $receipt.core_http_health_called -ne $false) {
        throw 'INSTALL_RECEIPT_REJECTED'
    }
    $payload = $receipt | ConvertTo-Json -Compress
    Write-AtomicInstallReceipt -Payload $payload
    $payload
    exit 0
}
catch {
    $failure = $_.Exception.Message
    if ($failure -notmatch '^[A-Z0-9_]+$') {
        $failure = 'INSPECTION_ERROR'
    }
    $payload = [pscustomobject][ordered]@{
        schema = 'myuna.host-cold-boot-install-failure.v1'
        status = 'INSTALL_FAILED_SANITIZED'
        failure_class = $failure
        release = $ReleaseDigest
        autologon_changed = $false
        reboot_performed = $false
        wsl_terminated = $false
        real_e2e = $false
        core_http_health_called = $false
    } | ConvertTo-Json -Compress
    Write-AtomicInstallReceipt -Payload $payload
    $payload
    exit 1
}
