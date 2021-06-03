function Get-SyncDiagnosticsLogPath {
    [CmdletBinding()]
    param()
    Resolve-Path "$($env:LOCALAPPDATA)\Microsoft\OneDrive\logs\*\SyncDiagnostics.log"
}

function Test-OdSyncService {
    <#
    .NOTES
    From https://www.cyberdrain.com/monitoring-with-powershell-monitoring-onedrive-status-for-current-logged-on-user/
    Modified by Tony Pagliaro

    Version 3 required for Unblock-File cmdlet.
    #>
    [CmdletBinding()]

    $Source = @"
        using System;  
        using System.Runtime.InteropServices;

        namespace murrayju.ProcessExtensions  
        {
            public static class ProcessExtensions
            {
                #region Win32 Constants

                private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
                private const int CREATE_NO_WINDOW = 0x08000000;

                private const int CREATE_NEW_CONSOLE = 0x00000010;

                private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
                private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

                #endregion

                #region DllImports

                [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
                private static extern bool CreateProcessAsUser(
                    IntPtr hToken,
                    String lpApplicationName,
                    String lpCommandLine,
                    IntPtr lpProcessAttributes,
                    IntPtr lpThreadAttributes,
                    bool bInheritHandle,
                    uint dwCreationFlags,
                    IntPtr lpEnvironment,
                    String lpCurrentDirectory,
                    ref STARTUPINFO lpStartupInfo,
                    out PROCESS_INFORMATION lpProcessInformation);

                [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
                private static extern bool DuplicateTokenEx(
                    IntPtr ExistingTokenHandle,
                    uint dwDesiredAccess,
                    IntPtr lpThreadAttributes,
                    int TokenType,
                    int ImpersonationLevel,
                    ref IntPtr DuplicateTokenHandle);

                [DllImport("userenv.dll", SetLastError = true)]
                private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

                [DllImport("userenv.dll", SetLastError = true)]
                [return: MarshalAs(UnmanagedType.Bool)]
                private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

                [DllImport("kernel32.dll", SetLastError = true)]
                private static extern bool CloseHandle(IntPtr hSnapshot);

                [DllImport("kernel32.dll")]
                private static extern uint WTSGetActiveConsoleSessionId();

                [DllImport("Wtsapi32.dll")]
                private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

                [DllImport("wtsapi32.dll", SetLastError = true)]
                private static extern int WTSEnumerateSessions(
                    IntPtr hServer,
                    int Reserved,
                    int Version,
                    ref IntPtr ppSessionInfo,
                    ref int pCount);

                #endregion

                #region Win32 Structs

                private enum SW
                {
                    SW_HIDE = 0,
                    SW_SHOWNORMAL = 1,
                    SW_NORMAL = 1,
                    SW_SHOWMINIMIZED = 2,
                    SW_SHOWMAXIMIZED = 3,
                    SW_MAXIMIZE = 3,
                    SW_SHOWNOACTIVATE = 4,
                    SW_SHOW = 5,
                    SW_MINIMIZE = 6,
                    SW_SHOWMINNOACTIVE = 7,
                    SW_SHOWNA = 8,
                    SW_RESTORE = 9,
                    SW_SHOWDEFAULT = 10,
                    SW_MAX = 10
                }

                private enum WTS_CONNECTSTATE_CLASS
                {
                    WTSActive,
                    WTSConnected,
                    WTSConnectQuery,
                    WTSShadow,
                    WTSDisconnected,
                    WTSIdle,
                    WTSListen,
                    WTSReset,
                    WTSDown,
                    WTSInit
                }

                [StructLayout(LayoutKind.Sequential)]
                private struct PROCESS_INFORMATION
                {
                    public IntPtr hProcess;
                    public IntPtr hThread;
                    public uint dwProcessId;
                    public uint dwThreadId;
                }

                private enum SECURITY_IMPERSONATION_LEVEL
                {
                    SecurityAnonymous = 0,
                    SecurityIdentification = 1,
                    SecurityImpersonation = 2,
                    SecurityDelegation = 3,
                }

                [StructLayout(LayoutKind.Sequential)]
                private struct STARTUPINFO
                {
                    public int cb;
                    public String lpReserved;
                    public String lpDesktop;
                    public String lpTitle;
                    public uint dwX;
                    public uint dwY;
                    public uint dwXSize;
                    public uint dwYSize;
                    public uint dwXCountChars;
                    public uint dwYCountChars;
                    public uint dwFillAttribute;
                    public uint dwFlags;
                    public short wShowWindow;
                    public short cbReserved2;
                    public IntPtr lpReserved2;
                    public IntPtr hStdInput;
                    public IntPtr hStdOutput;
                    public IntPtr hStdError;
                }

                private enum TOKEN_TYPE
                {
                    TokenPrimary = 1,
                    TokenImpersonation = 2
                }

                [StructLayout(LayoutKind.Sequential)]
                private struct WTS_SESSION_INFO
                {
                    public readonly UInt32 SessionID;

                    [MarshalAs(UnmanagedType.LPStr)]
                    public readonly String pWinStationName;

                    public readonly WTS_CONNECTSTATE_CLASS State;
                }

                #endregion

                // Gets the user token from the currently active session
                private static bool GetSessionUserToken(ref IntPtr phUserToken)
                {
                    var bResult = false;
                    var hImpersonationToken = IntPtr.Zero;
                    var activeSessionId = INVALID_SESSION_ID;
                    var pSessionInfo = IntPtr.Zero;
                    var sessionCount = 0;

                    // Get a handle to the user access token for the current active session.
                    if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
                    {
                        var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                        var current = pSessionInfo;

                        for (var i = 0; i < sessionCount; i++)
                        {
                            var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                            current += arrayElementSize;

                            if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                            {
                                activeSessionId = si.SessionID;
                            }
                        }
                    }

                    // If enumerating did not work, fall back to the old method
                    if (activeSessionId == INVALID_SESSION_ID)
                    {
                        activeSessionId = WTSGetActiveConsoleSessionId();
                    }

                    if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
                    {
                        // Convert the impersonation token to a primary token
                        bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                            (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
                            ref phUserToken);

                        CloseHandle(hImpersonationToken);
                    }

                    return bResult;
                }

                public static bool StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true)
                {
                    var hUserToken = IntPtr.Zero;
                    var startInfo = new STARTUPINFO();
                    var procInfo = new PROCESS_INFORMATION();
                    var pEnv = IntPtr.Zero;
                    int iResultOfCreateProcessAsUser;

                    startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

                    try
                    {
                        if (!GetSessionUserToken(ref hUserToken))
                        {
                            throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken failed.");
                        }

                        uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                        startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                        startInfo.lpDesktop = "winsta0\\default";

                        if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                        {
                            throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                        }

                        if (!CreateProcessAsUser(hUserToken,
                            appPath, // Application Name
                            cmdLine, // Command Line
                            IntPtr.Zero,
                            IntPtr.Zero,
                            false,
                            dwCreationFlags,
                            pEnv,
                            workDir, // Working directory
                            ref startInfo,
                            out procInfo))
                        {
                            throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.\n");
                        }

                        iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
                    }
                    finally
                    {
                        CloseHandle(hUserToken);
                        if (pEnv != IntPtr.Zero)
                        {
                            DestroyEnvironmentBlock(pEnv);
                        }
                        CloseHandle(procInfo.hThread);
                        CloseHandle(procInfo.hProcess);
                    }
                    return true;
                }
            }
        }
"@

    $jsonODLogParent = 'C:\programdata\Microsoft OneDrive'
    $DllFilePath = Join-Path $jsonODLogParent 'OneDriveLib.dll'
    $DllUri = 'https://raw.githubusercontent.com/rodneyviana/ODSyncService/master/Binaries/PowerShell/OneDriveLib.dll'
    if (Test-Path $DllFilePath) {} else {
        New-Item (Split-Path $DllFilePath -Parent) -ItemType directory -Force -ErrorAction SilentlyContinue | Out-Null
        Invoke-WebRequest -Uri $DllUri -OutFile $DllFilePath
        Unblock-File $DllFilePath
    }


    Add-Type -ReferencedAssemblies 'System', 'System.Runtime.InteropServices' -TypeDefinition $Source -Language CSharp
    $Now = Get-Date
    $LoggingFileBasename = 'OneDriveLogging'
    $jsonODLogParent = 'C:\programdata\Microsoft OneDrive'
    $jsonODLogging = Join-Path $jsonODLogParent "$($LoggingFileBasename).txt"
    $NewName = "$($LoggingFileBasename).$($Now.ToString('yyyyMMddHHmmss')).txt"
    $ChildName = Join-Path $jsonODLogParent "$($LoggingFileBasename).*.txt"
    $scriptblock = {
        Import-Module $DllFilePath
        Get-ODStatus | ConvertTo-Json | Out-File $jsonODLogging
    }
    Try {
        $null = [murrayju.ProcessExtensions.ProcessExtensions]::StartProcessAsCurrentUser(
            "C:\Windows\System32\WindowsPowershell\v1.0\Powershell.exe",
            "-command $($scriptblock)",
            "C:\Windows\System32\WindowsPowershell\v1.0",
            $false
        )
    } Catch {
        if ($_ -like '**') {
            $whoami = Invoke-Expression 'whoami' | Out-String
            Write-Error "Error starting process as user. You must be running this impersonation command as system. You are running it as $($whoami)."
        }
    }
    start-sleep 5


    $eLogPath = Join-Path $jsonODLogParent 'OdsmLogBackupErrors.txt'
    $eLogRetentionDays = 14
    #$ErrorList = @("NotInstalled", "ReadOnly", "Error", "OndemandOrUnknown")
    $ErrorList = @("NotInstalled", "ReadOnly", "Error") # Removed 'OndemandOrUnknown' as error condition
    Try {
        $ODStatus = (get-content $jsonODLogging -ea Stop | convertfrom-json).value
    } Catch {
        Write-Host "DEBUG: scriptblock: `n$($scriptblock)"
        throw "Error reading exported status file. $($_.Exception.Message)"
    } Finally {
        $eLog=$null
        Rename-Item $jsonODLogging -NewName $NewName -Force -ea 0 -ev eLog
        Get-ChildItem $ChildName -ea 0 |
            Where-Object {$_.LastWriteTime -lt ($Now.AddDays(-$eLogRetentionDays))} |
            Remove-Item -Confirm:$false -Force
        if ($eLog) {$eLog | Format-List * | Out-File $eLogPath -Append}
    }

    $ODerrors = New-Object System.Collections.ArrayList
    foreach ($ODStat in $ODStatus) {
        if ($ODStat.StatusString -in $ErrorList) {
            $thisResult = "$($ODStat.LocalPath) is in state $($ODStat.StatusString)"
            [void] ($ODerrors.Add($thisResult))
        }
    }


    if ($ODerrors) {
        Write-Host ($ODerrors -join ', ' | Out-String)
        # Write-Output gives errors for some reason, like it's running the string as a command
    } else {
        Write-Host "Healthy"
    }

}#END function Test-OdSyncService
