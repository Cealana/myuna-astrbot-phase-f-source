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
$expectedFiles = @(
    'ADR-037-host-cold-boot-recovery-v1.md',
    'Install-MyunaHostColdBootRelease.ps1',
    'Install-MyunaHostColdBootTask.ps1',
    'Invoke-MyunaHostColdBootInstall.ps1',
    'MANIFEST.json',
    'Start-MyunaHostColdBoot.ps1',
    'Start-MyunaHostColdBoot.vbs',
    'Start-PandaFanAutoconnect.ps1',
    'Test-MyunaHostColdBoot.ps1',
    'Test-MyunaAutologonState.ps1',
    'host_cold_boot_readiness_v1.py',
    'install_host_cold_boot_release_v1.py'
)
$manifestPayloads = $expectedFiles | Where-Object { $_ -ne 'MANIFEST.json' }
$releaseParent = Join-Path $env:ProgramFiles 'MyunaServer\HostColdBoot\releases'
$releaseDestination = Join-Path $releaseParent $ReleaseDigest
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
        # Windows PowerShell 5.1 converts any WSL stderr warning into a
        # NativeCommandError when the caller uses Stop. Preserve fail-closed
        # behavior via the native exit code while keeping stdout parseable.
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

function ConvertTo-WslDrivePath {
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath -notmatch '^([A-Za-z]):\\(.+)$') {
        throw 'WSL_STAGE_PATH_REJECTED'
    }
    $drive = $Matches[1].ToLowerInvariant()
    $tail = $Matches[2].Replace('\', '/')
    return "/mnt/$drive/$tail"
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'ADMINISTRATOR_REQUIRED'
    }
}

function Test-ExactRelease {
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or
        $item.Name -ne $ReleaseDigest -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'WINDOWS_RELEASE_SOURCE_REJECTED'
    }
    $children = @(Get-ChildItem -LiteralPath $item.FullName -Force)
    if ($children.Count -ne $expectedFiles.Count -or
        @($children | Where-Object {
            $_.PSIsContainer -or
            (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            $_.Name -notin $expectedFiles
        }).Count -ne 0 -or
        @($expectedFiles | Where-Object { $_ -notin $children.Name }).Count -ne 0) {
        throw 'WINDOWS_RELEASE_FILE_SET_REJECTED'
    }

    $manifestPath = Join-Path $item.FullName 'MANIFEST.json'
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ReleaseDigest) {
        throw 'WINDOWS_RELEASE_MANIFEST_DIGEST_REJECTED'
    }
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw 'WINDOWS_RELEASE_MANIFEST_DECODE_REJECTED'
    }
    $manifestProperties = @($manifest.PSObject.Properties.Name)
    if ($manifestProperties.Count -ne 3 -or
        @(@('files', 'schema', 'source_commit') | Where-Object { $_ -notin $manifestProperties }).Count -ne 0 -or
        $manifest.schema -ne 'myuna.host-cold-boot-release.v1' -or
        $manifest.source_commit -notmatch '^[0-9a-f]{40}$|^[0-9a-f]{64}$' -or
        @($manifest.files).Count -ne $manifestPayloads.Count) {
        throw 'WINDOWS_RELEASE_MANIFEST_SHAPE_REJECTED'
    }
    $manifestPaths = @($manifest.files | ForEach-Object { $_.path })
    if (@($manifestPayloads | Where-Object { $_ -notin $manifestPaths }).Count -ne 0 -or
        @($manifestPaths | Where-Object { $_ -notin $manifestPayloads }).Count -ne 0 -or
        @($manifestPaths | Select-Object -Unique).Count -ne $manifestPayloads.Count) {
        throw 'WINDOWS_RELEASE_MANIFEST_PATHS_REJECTED'
    }
    foreach ($entry in $manifest.files) {
        $entryProperties = @($entry.PSObject.Properties.Name)
        if ($entryProperties.Count -ne 4 -or
            @(@('mode', 'path', 'sha256', 'size') | Where-Object { $_ -notin $entryProperties }).Count -ne 0 -or
            $entry.mode -notin @('0444', '0555') -or
            $entry.sha256 -notmatch '^[0-9a-f]{64}$' -or
            $entry.size -isnot [ValueType]) {
            throw 'WINDOWS_RELEASE_MANIFEST_ENTRY_REJECTED'
        }
        $payloadPath = Join-Path $item.FullName $entry.path
        $payload = Get-Item -LiteralPath $payloadPath
        if ($payload.Length -ne [long]$entry.size -or
            (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) {
            throw 'WINDOWS_RELEASE_PAYLOAD_REJECTED'
        }
    }
    return $item.FullName
}

function Protect-ReleaseAcl {
    param([Parameter(Mandatory)][string]$Path)

    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $none = [Security.AccessControl.PropagationFlags]::None
    $directoryInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit

    $targets = @(
        [pscustomobject]@{ Path = $Path; Inheritance = $directoryInheritance }
    )
    $targets += @(Get-ChildItem -LiteralPath $Path -Force | ForEach-Object {
        [pscustomobject]@{
            Path = $_.FullName
            Inheritance = [Security.AccessControl.InheritanceFlags]::None
        }
    })

    foreach ($target in $targets) {
        $acl = Get-Acl -LiteralPath $target.Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($existingRule in @($acl.Access)) {
            $acl.RemoveAccessRuleAll($existingRule)
        }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $systemSid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $target.Inheritance,
            $none,
            $allow
        ))
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $administratorsSid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $target.Inheritance,
            $none,
            $allow
        ))
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $usersSid,
            [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            $target.Inheritance,
            $none,
            $allow
        ))
        Set-Acl -LiteralPath $target.Path -AclObject $acl

        $postAcl = Get-Acl -LiteralPath $target.Path
        $postRules = @($postAcl.Access)
        $writeMask = [Security.AccessControl.FileSystemRights]::WriteData -bor
            [Security.AccessControl.FileSystemRights]::AppendData -bor
            [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
            [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
            [Security.AccessControl.FileSystemRights]::Delete -bor
            [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [Security.AccessControl.FileSystemRights]::TakeOwnership
        $rules = @{}
        foreach ($rule in $postRules) {
            $sid = $rule.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]
            ).Value
            $rules[$sid] = $rule
        }
        if (-not $postAcl.AreAccessRulesProtected -or
            $postRules.Count -ne 3 -or
            @(@($systemSid.Value, $administratorsSid.Value, $usersSid.Value) | Where-Object { -not $rules.ContainsKey($_) }).Count -ne 0 -or
            ($rules[$systemSid.Value].FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            ($rules[$administratorsSid.Value].FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            ($rules[$usersSid.Value].FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -ne [Security.AccessControl.FileSystemRights]::ReadAndExecute -or
            ($rules[$usersSid.Value].FileSystemRights -band $writeMask) -ne 0) {
            throw 'WINDOWS_RELEASE_ACL_REJECTED'
        }
    }
}

Assert-Administrator
$resolvedStage = Test-ExactRelease -Path (Resolve-Path -LiteralPath $StagedRelease).Path
New-Item -ItemType Directory -Force -Path $releaseParent | Out-Null
$createdWindowsRelease = $false

if (Test-Path -LiteralPath $releaseDestination) {
    $null = Test-ExactRelease -Path $releaseDestination
}
else {
    $temporary = Join-Path $releaseParent ('.' + $ReleaseDigest + '.install-' + [guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $temporary | Out-Null
        foreach ($name in $expectedFiles) {
            Copy-Item -LiteralPath (Join-Path $resolvedStage $name) -Destination (Join-Path $temporary $name)
        }
        Protect-ReleaseAcl -Path $temporary
        [IO.Directory]::Move($temporary, $releaseDestination)
        $createdWindowsRelease = $true
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Recurse -Force
        }
    }
    $null = Test-ExactRelease -Path $releaseDestination
}
Protect-ReleaseAcl -Path $releaseDestination

$linuxStage = ConvertTo-WslDrivePath -Path $resolvedStage
if ($linuxStage -notmatch '^/mnt/[a-z]/') {
    throw 'WSL_STAGE_PATH_REJECTED'
}
$linuxInstaller = "$linuxStage/install_host_cold_boot_release_v1.py"
$linuxInstallProbe = Invoke-WslNative -ArgumentList @('-d', 'Server-Ubuntu', '-u', 'root', '--', '/usr/bin/python3', $linuxInstaller, $linuxStage, $ReleaseDigest)
if ($linuxInstallProbe.ExitCode -ne 0) {
    throw 'LINUX_RELEASE_INSTALL_REJECTED'
}
try {
    $linuxReceipt = ($linuxInstallProbe.Output -join "`n") | ConvertFrom-Json -ErrorAction Stop
}
catch {
    throw 'LINUX_RELEASE_RECEIPT_REJECTED'
}
if ($linuxReceipt.status -ne 'INSTALLED_INACTIVE' -or $linuxReceipt.release -ne $ReleaseDigest) {
    throw 'LINUX_RELEASE_POSTSTATE_REJECTED'
}

$taskInstaller = Join-Path $releaseDestination 'Install-MyunaHostColdBootTask.ps1'
$taskArguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $taskInstaller, '-ReleaseDigest', $ReleaseDigest)
if ($StartNow) {
    $taskArguments += '-StartNow'
}
if ($LockAfterReady) {
    $taskArguments += '-LockAfterReady'
}
$taskReceiptText = & $windowsPowerShell @taskArguments
if ($LASTEXITCODE -ne 0) {
    throw 'TASK_INSTALL_REJECTED_RELEASES_RETAINED_INACTIVE'
}
try {
    $taskReceipt = $taskReceiptText | ConvertFrom-Json -ErrorAction Stop
}
catch {
    throw 'TASK_INSTALL_RECEIPT_REJECTED_RELEASES_RETAINED_INACTIVE'
}
$expectedTaskStatus = if ($StartNow) { 'INSTALLED_READY_NO_AUDIT' } else { 'INSTALLED_INACTIVE' }
if ($taskReceipt.status -ne $expectedTaskStatus -or
    $taskReceipt.release -ne $ReleaseDigest -or
    $taskReceipt.lock_after_ready -ne [bool]$LockAfterReady) {
    throw 'TASK_INSTALL_POSTSTATE_REJECTED_RELEASES_RETAINED_INACTIVE'
}

[pscustomobject][ordered]@{
    schema = 'myuna.host-cold-boot-release-install.v1'
    status = $taskReceipt.status
    release = $ReleaseDigest
    windows_release_created = $createdWindowsRelease
    linux_release_created = [bool]$linuxReceipt.created
    task = $taskReceipt.task
    started = [bool]$StartNow
    lock_after_ready = [bool]$LockAfterReady
    autologon_changed = $false
    reboot_performed = $false
    wsl_terminated = $false
    real_e2e = $false
    core_http_health_called = $false
} | ConvertTo-Json -Compress
