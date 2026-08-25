[CmdletBinding()]
param([switch]$CleanupOrphans)

$ErrorActionPreference = 'Stop'
$temporaryRoot = [IO.Path]::GetTempPath()
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
if ($CleanupOrphans) {
    $removed = 0
    foreach ($orphan in @(Get-ChildItem -LiteralPath $temporaryRoot -Directory -Filter 'MyunaHostColdBootAcl-*')) {
        $resolvedOrphan = (Resolve-Path -LiteralPath $orphan.FullName).Path
        if (-not $resolvedOrphan.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $resolvedOrphan) -notlike 'MyunaHostColdBootAcl-*') {
            throw 'ACL_SELF_TEST_ORPHAN_REJECTED'
        }
        & "$env:WINDIR\System32\icacls.exe" $resolvedOrphan `
            '/inheritance:e' `
            '/grant:r' `
            "*$($currentSid.Value):(OI)(CI)F" `
            '/T' '/C' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'ACL_SELF_TEST_CLEANUP_REJECTED'
        }
        Remove-Item -LiteralPath $resolvedOrphan -Recurse -Force
        $removed += 1
    }
    "ACL_SELF_TEST_ORPHANS_REMOVED=$removed"
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$installer = Join-Path $root 'scripts\windows\Install-MyunaHostColdBootRelease.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $installer,
    [ref]$tokens,
    [ref]$errors
)
if (@($errors).Count -ne 0) {
    throw 'INSTALLER_PARSE_REJECTED'
}
$function = $ast.FindAll(
    {
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Protect-ReleaseAcl'
    },
    $true
)
if (@($function).Count -ne 1) {
    throw 'ACL_FUNCTION_REJECTED'
}
Invoke-Expression $function[0].Extent.Text

$temporary = Join-Path $temporaryRoot ('MyunaHostColdBootAcl-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
$files = @(
    (New-Item -ItemType File -Path (Join-Path $temporary 'one.test')).FullName,
    (New-Item -ItemType File -Path (Join-Path $temporary 'two.test')).FullName
)
try {
    Protect-ReleaseAcl -Path $temporary
    foreach ($file in $files) {
        $stream = [IO.File]::OpenRead($file)
        $stream.Dispose()
    }
    $usersSid = 'S-1-5-32-545'
    foreach ($path in @($temporary) + $files) {
        $acl = Get-Acl -LiteralPath $path
        $usersRules = @($acl.Access | Where-Object {
            $_.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]
            ).Value -eq $usersSid
        })
        if (-not $acl.AreAccessRulesProtected -or $usersRules.Count -ne 1) {
            throw 'ACL_SELF_TEST_REJECTED'
        }
    }
    'ACL_SELF_TEST_OK'
}
finally {
    if (Test-Path -LiteralPath $temporary) {
        & "$env:WINDIR\System32\icacls.exe" $temporary `
            '/inheritance:e' `
            '/grant:r' `
            "*$($currentSid.Value):(OI)(CI)F" `
            '/T' '/C' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'ACL_SELF_TEST_CLEANUP_REJECTED'
        }
        $resolved = (Resolve-Path -LiteralPath $temporary).Path
        if ($resolved.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -and
            (Split-Path -Leaf $resolved) -like 'MyunaHostColdBootAcl-*') {
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
    }
}
