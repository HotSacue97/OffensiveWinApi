// This code hides a dll from on of the lists in memory, for for stealth you should do the same for all lists in memory:
//	InLoadOrderMouduleList;
//	InMemoryOrderMouduleList;
//	InInitializationOrderMouduleList;
// I just hidden the first module in the list, but you an of course change it and hide what ever module you like by name
// By changing line 107 with the comment - Instead can insert here any dll name

#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <Psapi.h>

typedef struct _Peb_Ldr_Data
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderMouduleList;
	LIST_ENTRY InMemoryOrderMouduleList;
	LIST_ENTRY InInitializationOrderMouduleList;
	PVOID EntryInProgress;
} Peb_Ldr_Data, * PPeb_Ldr_Data;

typedef struct _Ldr_Data_Table_Entry
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderlinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG sizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Falgs;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} Ldr_Data_Table_Entry, * PLdr_Data_Table_Entry;

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

int _tmain(int argc, const TCHAR* argv[])
{
	// Get handle to my own process 
	PEB peb;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());

	// Get Peb address
	DWORD dwSize;
	typedef LONG(WINAPI NTQIP)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
	NTQIP* lpfnNtQueryInformationProcess;
	PROCESS_BASIC_INFORMATION pbi;
	HMODULE hLibrary = GetModuleHandle(_T("ntdll.dll"));

	if (hLibrary != NULL)
	{
		lpfnNtQueryInformationProcess = (NTQIP*)GetProcAddress(hLibrary, "NtQueryInformationProcess");
		(*lpfnNtQueryInformationProcess)(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &dwSize);
	}
	else 
	{
		wprintf(L"Can't get peb address\n");
		return 1;
	}

	SIZE_T buffer;
	ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), &buffer);

	// Get Ldr
	PPeb_Ldr_Data ldr = (PPeb_Ldr_Data)peb.Ldr;

	// Get first entry of InMemoryOrderModuleList
	_Ldr_Data_Table_Entry* module = (_Ldr_Data_Table_Entry*)ldr->InLoadOrderMouduleList.Flink;
	PWSTR first_module = module->FullDllName.Buffer; // Instead can insert here any dll name
	module = (_Ldr_Data_Table_Entry*)module->InLoadOrderLinks.Flink;
	PWSTR module_name = module->FullDllName.Buffer;

	// Print all modules
	while (wcscmp(module_name, first_module) != 0)
	{
		wprintf(L"Module name : % s\n", module_name);
		module = (_Ldr_Data_Table_Entry*)module->InLoadOrderLinks.Flink;
		module_name = module->FullDllName.Buffer;
	}
	wprintf(L"\n\n");

	// Disconnect module
	_Ldr_Data_Table_Entry* before = (_Ldr_Data_Table_Entry*)module->InLoadOrderLinks.Blink;
	_Ldr_Data_Table_Entry* after = (_Ldr_Data_Table_Entry*)module->InLoadOrderLinks.Flink;
	module->InLoadOrderLinks.Blink->Flink = (_LIST_ENTRY*)after;
	module->InLoadOrderLinks.Flink->Blink = (_LIST_ENTRY*)before;
}
