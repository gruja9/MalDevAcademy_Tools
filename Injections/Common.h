#pragma once

#include <windows.h>
#include <Shlwapi.h>

#include "Structs.h"

#define MAX_PATH 32
#define MAX_PROCESSES 256

#define STATUS_SUCCESS				0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004


typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

//HelperFunctions.c
BOOL ReportErrorWinAPI(char* ApiName);
BOOL ReportErrorNTAPI(char* ApiName, NTSTATUS STATUS);
BOOL ConvertToLowerCase(IN LPCWSTR lpszInput, OUT LPWSTR* pOutput);
void AlertableSleepEx();
void AlertableWaitForSingleObjectEx();
void AlertableWaitForMultipleObjectsEx();
void AlertableMsgWaitForMultipleObjectsEx();
void AlertableSignalObjectAndWait();
void DummyFunction();
DWORD HashStringDjb2A(IN PCHAR String);
DWORD HashStringDjb2W(IN PWCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitA(IN PCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitW(IN PWCHAR String);
DWORD HashStringLoseLoseA(IN PCHAR String);
DWORD HashStringLoseLoseW(IN PWCHAR String);
INT HashStringRotr32A(IN PCHAR String);
INT HashStringRotr32W(IN PWCHAR String);

// IO.c
BOOL FileExists(IN LPCSTR lpPath);
BOOL ReadShellcodeFromFile(IN LPCSTR lpPath, OUT PVOID* pShellcode, OUT SIZE_T* dwShellcodeSize);
BOOL IsUrl(IN LPCSTR lpUrl);
BOOL IsDll(IN LPCSTR lpPath);
BOOL ReadShellcodeFromURL(IN LPCSTR lpUrl, OUT PVOID* pShellcode, OUT SIZE_T* sShellcodeSize);
BOOL FetchShellcode(IN LPCSTR lpShellcodePath, OUT PVOID* pShellcode, OUT SIZE_T* sShellcodeSize);

// Internals.c
BOOL ObtainWinAPIAddress(IN LPCSTR lpDllName, IN LPCSTR lpFunctionName, OUT PVOID* pAddress);
BOOL IsAlreadyRunning();
BOOL AllocateMemory(IN DWORD dwType, IN HANDLE hProcess, IN PVOID pShellcode, IN SIZE_T sShellcodeSize, OUT PVOID* pShellcodeAddr);
BOOL RunThread(IN HANDLE hProcess, IN BOOL bSuspended, IN PVOID pShellcode, OUT HANDLE* hThread, OUT DWORD* dwThreadId);
BOOL WaitForThread(IN HANDLE hThread);
BOOL FreeMemory(IN DWORD dwMemoryType, IN HANDLE hProcess, IN PVOID pShellcode);
BOOL ObtainProcessHandle(IN DWORD Method, IN LPCSTR lpProcessName, OUT HANDLE* hProcess, OUT DWORD* dwProcessId);
BOOL ObtainThreadHandle(IN DWORD dwMethod, IN DWORD dwProcessId, IN DWORD dwMainThreadId, OUT HANDLE* hThread, OUT DWORD* dwThreadId);
BOOL HijackThread(IN HANDLE hThread, IN PVOID pShellcodeAddr);
BOOL CreateAlertableThread(IN HANDLE hProcess, IN DWORD dwAlertableFunction, OUT HANDLE* hThread, OUT DWORD* dwThreadId);
BOOL CreateNewProcess(IN DWORD dwCreationFlag, IN LPCSTR lpProcessName, OUT HANDLE* hProcess, OUT HANDLE* hThread, OUT DWORD* dwProcessId);
BOOL CreatePPIDSpoofedProcess(IN DWORD dwCreationFlags, IN LPCSTR lpProcessName, IN LPCSTR lpParentProcessName, OUT HANDLE* hProcess, OUT HANDLE* hThread);
BOOL RetrievePEB(IN HANDLE hProcess, OUT PVOID* pPebAddress, OUT PPEB* pPeb);

// Process.c
BOOL LocalProcessInjection(IN DWORD dwMemoryType, IN LPCSTR ShellcodePath);
BOOL RemoteProcessInjection(IN DWORD dwMemoryType, IN LPCSTR lpProcessName, IN DWORD dwEnumerationMethod, IN LPCSTR lpShellcodePath);
BOOL LocalProcessDllInjection(IN LPCSTR lpShellcodePath);
BOOL RemoteProcessDllInjection(IN DWORD dwMemoryType, IN LPCSTR lpProcessName, IN DWORD dwEnumerationMethod, IN LPCSTR lpShellcodePath);
BOOL PPIDSpoofing(IN LPCSTR lpProcessName, IN LPCSTR lpParentProcessName, IN LPCSTR lpShellcodePath);

// Thread.c
BOOL LocalThreadHijacking(IN LPCSTR lpShellcodePath, IN DWORD dwMainThreadId);
BOOL RemoteThreadHijacking(IN LPCSTR lpProcessName, IN DWORD dwThreadEnumerationMethod, IN LPCSTR lpShellcodePath);
BOOL ApcInjection(IN BOOL bAlertable, IN DWORD dwAlertableFunction, IN LPCSTR lpProcessName, IN LPCSTR lpShellcodePath);
BOOL ApcHijacking(IN LPCSTR lpProcessName, IN LPCSTR lpShellcodePath);
BOOL EarlyBirdApcInjection(IN DWORD dwCreationFlag, IN LPCSTR lpProcessName, IN LPCSTR lpShellcodePath);

// Threadless.c
BOOL CallbackFunction(IN LPCSTR lpShellcodePath);

// Other.c
BOOL ArgumentSpoofing(IN LPCSTR lpProcessName, IN LPCSTR lpFakeArgs, IN LPCSTR lpRealArgs);

//Injections.c (main)
int PrintHelp(char* argv0, char* function);