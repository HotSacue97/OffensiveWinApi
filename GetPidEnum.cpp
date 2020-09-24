//Function get a process name as argument, and return its pid

#include <stdio.h>
#include <Windows.h>
#include <tchar.h>
#include <Psapi.h>

#define MAX_LEN 1024

DWORD GetPid(TCHAR* ProcName)
{
	DWORD processes[1024], num;
	EnumProcesses(processes, sizeof(processes), &num);
	for (DWORD i = 0; i < num / sizeof(DWORD); i++)
	{
		if (processes[i] != 0)
		{
			TCHAR name[MAX_LEN] = _T("unknown process");
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processes[i]);
			if (hProcess != NULL)
			{
				HMODULE hMod;
				DWORD cbNeeded;
				if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod), &cbNeeded, LIST_MODULES_ALL))
				{
					
					GetModuleBaseName(hProcess, hMod, name, sizeof(name) / sizeof(TCHAR));
				}
				CloseHandle(hProcess);
				if (_tcscmp(ProcName, name) == 0)
				{
					return processes[i];
				}
			}
		}
	}
}
