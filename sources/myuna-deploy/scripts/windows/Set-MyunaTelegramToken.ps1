[CmdletBinding()]
param(
    [switch]$Replace
)

$ErrorActionPreference = 'Stop'
$secureToken = Read-Host 'Paste the BotFather token (input is hidden)' -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
$plainToken = $null

try {
    $plainToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    if ([string]::IsNullOrWhiteSpace($plainToken)) {
        throw 'Telegram token intake rejected'
    }

    $arguments = @(
        '-d',
        'Server-Ubuntu',
        '--user',
        'root',
        '--',
        'python3',
        '/usr/local/libexec/myuna-telegram-gateway/telegram_bot_token_intake.py'
    )
    if ($Replace) {
        $arguments += '--replace'
    }

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = 'wsl.exe'
    foreach ($argument in $arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    [void]$process.Start()
    $process.StandardInput.WriteLine($plainToken)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    if ($process.ExitCode -ne 0) {
        throw 'Telegram token intake rejected'
    }
    if ($stderr) {
        throw 'Telegram token intake returned an unexpected diagnostic'
    }
    $result = $stdout | ConvertFrom-Json
    if ($result.result -ne 'telegram-bot-token-stored' -or $result.token_echoed) {
        throw 'Telegram token intake verification failed'
    }
    Write-Host 'Telegram Bot token stored without echoing or command-line exposure.'
}
finally {
    $plainToken = $null
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $secureToken.Dispose()
}
