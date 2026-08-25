[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedReleaseDigest,
    [string]$ExpectedUser = [Environment]::UserName,
    [switch]$RequireLockAfterReady
)

$ErrorActionPreference = 'Stop'
$winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$taskName = 'MyunaServer-Start-Server-Ubuntu'

try {
    $stage = 'registry-key'
    $key = Get-Item -LiteralPath $winlogonPath
    $stage = 'registry-values'
    $autoAdminLogon = if ($key.Property -contains 'AutoAdminLogon') {
        Get-ItemPropertyValue -LiteralPath $winlogonPath -Name 'AutoAdminLogon'
    }
    else { $null }
    $defaultUser = if ($key.Property -contains 'DefaultUserName') {
        Get-ItemPropertyValue -LiteralPath $winlogonPath -Name 'DefaultUserName'
    }
    else { $null }
    $defaultDomain = if ($key.Property -contains 'DefaultDomainName') {
        Get-ItemPropertyValue -LiteralPath $winlogonPath -Name 'DefaultDomainName'
    }
    else { $null }
    $plaintextPasswordPropertyPresent = $key.Property -contains 'DefaultPassword'
    $finiteCountConfigured = $key.Property -contains 'AutoLogonCount'
    $stage = 'scheduled-task'
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
    $taskArguments = $task.Actions[0].Arguments
    $candidateTask = $task.Actions.Count -eq 1 -and
        $taskArguments -like "*$ExpectedReleaseDigest*" -and
        $task.Principal.LogonType.ToString() -eq 'Interactive' -and
        $task.Principal.RunLevel.ToString() -eq 'Limited'
    $lockConfigured = $taskArguments -like '* --lock-after-ready'
    $domainMatches = [string]::IsNullOrWhiteSpace($defaultDomain) -or
        $defaultDomain -eq $env:COMPUTERNAME -or
        $defaultDomain -eq '.'
    $stage = 'evaluation'
    $ready = $autoAdminLogon -eq '1' -and
        $defaultUser -eq $ExpectedUser -and
        $domainMatches -and
        -not $plaintextPasswordPropertyPresent -and
        -not $finiteCountConfigured -and
        $candidateTask -and
        ($lockConfigured -eq [bool]$RequireLockAfterReady)

    [pscustomobject][ordered]@{
        schema = 'myuna.host-cold-boot-autologon-state.v1'
        status = $(if ($ready) { 'AUTOLOGON_READY_SANITIZED' } else { 'AUTOLOGON_NOT_READY' })
        autologon_enabled = $autoAdminLogon -eq '1'
        default_user_matches = $defaultUser -eq $ExpectedUser
        local_domain_matches = $domainMatches
        plaintext_registry_password_present = $plaintextPasswordPropertyPresent
        finite_autologon_count_configured = $finiteCountConfigured
        candidate_task = $candidateTask
        lock_after_ready = $lockConfigured
        lsa_secret_read = $false
        password_validated = $false
        password_exposed = $false
        release = $ExpectedReleaseDigest
    } | ConvertTo-Json -Compress
    exit $(if ($ready) { 0 } else { 1 })
}
catch {
    [pscustomobject][ordered]@{
        schema = 'myuna.host-cold-boot-autologon-state.v1'
        status = 'AUTOLOGON_INSPECTION_ERROR'
        failure_stage = $stage
        lsa_secret_read = $false
        password_validated = $false
        password_exposed = $false
        release = $ExpectedReleaseDigest
    } | ConvertTo-Json -Compress
    exit 2
}
