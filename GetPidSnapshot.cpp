#include <stdio.h>
#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>

#define MAX_LEN 1024

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
	TCHAR ProcName[MAX_LEN] = _T("winlogon.exe");
	GetPid(ProcName);
}