#include <windows.h>

/*
########## Error Reporting Functions ##########
*/

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


/*
########## Internals Helper Functions ##########
*/

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
			LowerName[i] = (WCHAR)tolower(lpszInput[i]);
		LowerName[i++] = '\0';
	}

	*pOutput = LowerName;

	return TRUE;
}


/*
########## Alertable Functions ##########
*/

void AlertableSleepEx()
{
	SleepEx(INFINITE, TRUE);
}

void AlertableWaitForSingleObjectEx()
{
	HANDLE hEvent;
	if ((hEvent = CreateEvent(NULL, NULL, NULL, NULL)) == NULL)
		return ReportErrorWinAPI("CreateEvent");

	WaitForSingleObjectEx(hEvent, INFINITE, TRUE);
	CloseHandle(hEvent);
}

void AlertableWaitForMultipleObjectsEx()
{
	HANDLE hEvent;
	if ((hEvent = CreateEvent(NULL, NULL, NULL, NULL)) == NULL)
		return ReportErrorWinAPI("CreateEvent");

	WaitForMultipleObjectsEx(1, &hEvent, TRUE, INFINITE, TRUE);
	CloseHandle(hEvent);
}

void AlertableMsgWaitForMultipleObjectsEx()
{
	HANDLE hEvent;
	if ((hEvent = CreateEvent(NULL, NULL, NULL, NULL)) == NULL)
		return ReportErrorWinAPI("CreateEvent");

	MsgWaitForMultipleObjectsEx(1, &hEvent, INFINITE, QS_KEY, MWMO_ALERTABLE);
	CloseHandle(hEvent);
}

void AlertableSignalObjectAndWait()
{
	HANDLE hEvent1, hEvent2;
	if ((hEvent1 = CreateEvent(NULL, NULL, NULL, NULL)) == NULL)
		return ReportErrorWinAPI("CreateEvent");
	if ((hEvent2 = CreateEvent(NULL, NULL, NULL, NULL)) == NULL)
		return ReportErrorWinAPI("CreateEvent");

	SignalObjectAndWait(hEvent1, hEvent2, INFINITE, TRUE);
	CloseHandle(hEvent1);
	CloseHandle(hEvent2);
}


/*
########## Dummy Functions ##########
*/

void DummyFunction()
{
	int i = rand();
	int j = i + rand();
}

/*
########## String Hashing Functions ##########
*/

#define INITIAL_HASH	3731  // added to randomize the hash
#define INITIAL_SEED	7

// generate Djb2 hashes from Ascii input string
DWORD HashStringDjb2A(IN PCHAR String)
{
	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}

// generate Djb2 hashes from wide-character input string
DWORD HashStringDjb2W(IN PWCHAR String)
{
	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}

// Generate JenkinsOneAtATime32Bit hashes from Ascii input string
UINT32 HashStringJenkinsOneAtATime32BitA(IN PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

// Generate JenkinsOneAtATime32Bit hashes from wide-character input string
UINT32 HashStringJenkinsOneAtATime32BitW(IN PWCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenW(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

// Generate LoseLose hashes from ASCII input string
DWORD HashStringLoseLoseA(IN PCHAR String)
{
	ULONG Hash = 0;
	INT c;

	while (c = *String++) {
		Hash += c;
		Hash *= c + INITIAL_SEED;	// update
	}
	return Hash;
}

// Generate LoseLose hashes from wide-character input string
DWORD HashStringLoseLoseW(IN PWCHAR String)
{
	ULONG Hash = 0;
	INT c;

	while (c = *String++) {
		Hash += c;
		Hash *= c + INITIAL_SEED;	// update
	}

	return Hash;
}

// Helper function that apply the bitwise rotation
UINT32 HashStringRotr32Sub(IN UINT32 Value, IN UINT Count)
{
	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
	return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

// Generate Rotr32 hashes from Ascii input string
INT HashStringRotr32A(IN PCHAR String)
{
	INT Value = 0;

	for (INT Index = 0; Index < lstrlenA(String); Index++)
		Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

	return Value;
}

// Generate Rotr32 hashes from wide-character input string
INT HashStringRotr32W(IN PWCHAR String)
{
	INT Value = 0;

	for (INT Index = 0; Index < lstrlenW(String); Index++)
		Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

	return Value;
}