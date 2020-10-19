//Enable SeDebugPrivilege - Can enable any privilege by changinge the TCHAR "SeDebugPrivilege" to the desired privilege
//Include validing if the privilege exist in the token, to be sure it can be enabled. This is important because the WinApi -"AdjustTokenPrivileges function
//Will return no error if the desired pirvilege is a valid privilege, but does not exist on the token, so you wont know it really worked, unless you have checked
//It exist in the Token

#include <stdio.h>
#include <Windows.h>
#include <tchar.h>

#define MAX_LEN 1024
int EnableDebug(void)
{
	LUID privilegeLuid;
	if (!LookupPrivilegeValue(NULL, _T("SeDebugPrivilege"), &privilegeLuid));
	{
		_tprintf(_T("Error - cant get privilege\n"));
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
		_tprintf(_T("Error - cant get token from process\n"));
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
