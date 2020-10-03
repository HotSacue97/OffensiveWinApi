# OffensiveWinApi
This repository includes POCs written in C/C++, manipulating the windows opearting systems using WinApi.
All of the POCs are for research purposes only.

##EnableDebug
Enable SeDebugPrivilege - Can enable any privilege by changinge the TCHAR "SeDebugPrivilege" to the desired privilege.
The code include validing if the privilege exist in the token, to be sure it can be enabled. This is important because the WinApi -"AdjustTokenPrivileges function
will return no error if the desired pirvilege is a valid privilege, but does not exist on the token, so you wont know it really worked, unless you have checked
it exist in the Token.

##GetPidEnum
Function get a process name as argument, and return its pid.
Using EnumProcesses.

##GetPidSnapshot
Function get a process name as argument, and return its pid.
Using CreateToolHelp32Snapshot.

#ParentSpoof
Spoofing a parent process. 
This program changes the AttributeList in the StartupInfo structure, and then the process created by CreatedProcess is created with new StartupInfo.
The chosen parent and child processes can be changes by changing constants.

#TokenStealer
Thie function steal a token from winlogon - one of the vulnerable processes with system token(privileges), and creates a new cmd with that token.
You can change the cmd.exe to anathor file by changing a constant.
