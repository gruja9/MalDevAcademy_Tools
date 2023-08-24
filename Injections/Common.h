#pragma once

#include <windows.h>

#include "Structs.h"

#define MAX_PATH 32
#define MAX_PROCESSES 256

enum PROCESS_ENUM
{
	SNAPSHOT,
	ENUMPROCESSES,
	NTQUERYSYSTEMINFORMATION
};

enum ALERTABLE_FUNCTIONS
{
	SLEEPEX,
	WAITFORSINGLEOBJECTEX,
	WAITFORMULTIPLEOBJECTSEX,
	MSGWAITFORMULTIPLEOBJECTSEX,
	SIGNALOBJECTANDWAIT
};

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

//HelperFunctions.c
void AlertableSleepEx();
void AlertableWaitForSingleObjectEx();
void AlertableWaitForMultipleObjectsEx();
void AlertableMsgWaitForMultipleObjectsEx();
void AlertableSignalObjectAndWait();
void DummyFunction();

// IO.c
BOOL FileExists(IN LPCSTR lpPath);
BOOL ReadShellcodeFromFile(IN LPCSTR lpPath, OUT PVOID* pShellcode, OUT SIZE_T* dwShellcodeSize);
BOOL IsUrl(IN LPCSTR lpUrl);
BOOL IsDll(IN LPCSTR lpPath);
BOOL IsAbsolutePath(IN LPCSTR lpPath);
BOOL ReadShellcodeFromURL(IN LPCSTR lpUrl, OUT PVOID* pShellcode, OUT SIZE_T* sShellcodeSize);
BOOL FetchShellcode(IN LPCSTR lpShellcodePath, OUT PVOID* pShellcode, OUT SIZE_T* sShellcodeSize);

// Internals.c
BOOL ReportErrorWinAPI(char* ApiName);
BOOL ConvertToLowerCase(IN LPCWSTR lpszInput, OUT LPWSTR* pOutput);
BOOL AllocateMemory(IN HANDLE hProcess, IN PVOID pShellcode, IN SIZE_T sShellcodeSize, OUT PVOID* pShellcodeAddr);
BOOL RunThread(IN HANDLE hProcess, IN BOOL bSuspended, IN PVOID pShellcode, OUT HANDLE* hThread, OUT DWORD* dwThreadId);
BOOL WaitForThread(IN HANDLE hThread);
BOOL FreeMemory(IN HANDLE hProcess, IN PVOID pShellcode);
BOOL ObtainProcessHandle(IN DWORD Method, IN LPCSTR lpProcessName, OUT HANDLE* hProcess, OUT DWORD* dwProcessId);
BOOL ObtainThreadHandle(IN DWORD dwProcessId, IN DWORD dwMainThreadId, OUT HANDLE* hThread, OUT DWORD* dwThreadId);
BOOL HijackThread(IN HANDLE hThread, IN PVOID pShellcodeAddr);
BOOL CreateAlertableThread(IN HANDLE hProcess, IN DWORD dwAlertableFunction, OUT HANDLE* hThread, OUT DWORD* dwThreadId);
BOOL RunProcess(IN DWORD dwCreationFlag, IN LPCSTR lpProcessName, OUT HANDLE* hProcess, OUT HANDLE* hThread, OUT DWORD* dwProcessId);

// Process.c
BOOL LocalProcessInjection(IN LPCSTR ShellcodePath);
BOOL RemoteProcessInjection(IN LPCSTR lpProcessName, IN DWORD dwEnumerationMethod, IN LPCSTR lpShellcodePath);
BOOL LocalProcessDllInjection(IN LPCSTR lpShellcodePath);
BOOL RemoteProcessDllInjection(IN LPCSTR lpProcessName, IN DWORD dwEnumerationMethod, IN LPCSTR lpShellcodePath);

// Thread.c
BOOL LocalThreadHijacking(IN LPCSTR lpShellcodePath, IN DWORD dwMainThreadId);
BOOL RemoteThreadHijacking(IN LPCSTR lpProcessName, IN LPCSTR lpShellcodePath);
BOOL ApcInjection(IN BOOL bAlertable, IN DWORD dwAlertableFunction, IN LPCSTR lpProcessName, IN LPCSTR lpShellcodePath);
BOOL ApcHijacking(IN LPCSTR lpProcessName, IN LPCSTR lpShellcodePath);
BOOL EarlyBirdApcInjection(IN DWORD dwCreationFlag, IN LPCSTR lpProcessName, IN LPCSTR lpShellcodePath);

//Injections.c (main)
int PrintHelp(char* argv0, char* function);