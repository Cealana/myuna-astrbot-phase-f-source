Option Explicit

If WScript.Arguments.Count < 2 Or WScript.Arguments.Count > 3 Then
    WScript.Quit 64
End If

Dim shell, powerShell, scriptPath, linuxPath, lockArgument, command, exitCode
Set shell = CreateObject("WScript.Shell")
powerShell = shell.ExpandEnvironmentStrings("%WINDIR%") & "\System32\WindowsPowerShell\v1.0\powershell.exe"
scriptPath = WScript.Arguments.Item(0)
linuxPath = WScript.Arguments.Item(1)
lockArgument = ""
If WScript.Arguments.Count = 3 Then
    If WScript.Arguments.Item(2) <> "--lock-after-ready" Then
        WScript.Quit 64
    End If
    lockArgument = " -LockAfterReady"
End If

command = Chr(34) & powerShell & Chr(34) & _
    " -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden" & _
    " -File " & Chr(34) & scriptPath & Chr(34) & _
    " -LinuxReadinessPath " & Chr(34) & linuxPath & Chr(34) & _
    lockArgument

exitCode = shell.Run(command, 0, True)
WScript.Quit exitCode
