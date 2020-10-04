#include <stdio.h>
#include <Windows.h>
#include <tchar.h>

int main(int argc, const char* argv[])
{
	if (argc < 3)
	{
		_tprintf(_T("Please enter <pid> <dllpath>\n"));
		return 1;
	}
	int pid = atoi(argv[1]);
	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, NULL, pid);

	if (!hProcess)
	{
		_tprintf(_T("Cant open target process\n"));
		return 1;
	}

	void* buffer = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buffer)
	{
		_tprintf(_T("Cant allocate memory in target process\n"));
		return 1;
	}
	printf("%d",!WriteProcessMemory(hProcess, buffer, argv[2], strlen(argv[2]), NULL));
	/*if(!WriteProcessMemory(hProcess, buffer, argv[2], _tcslen(argv[2]), NULL));
	{
		_tprintf(_T("Cant write memory in target process\n"));
		//return 1;
	}
	*/
	LPTHREAD_START_ROUTINE start = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(_T("kernel32")),("LoadLibraryA"));
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, start, buffer, NULL, NULL);
	if (!hThread)
	{
		_tprintf(_T("Cant create thread in target process\n"));
		return 1;
	}
}