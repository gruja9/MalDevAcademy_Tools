#include <windows.h>

// Helper functions
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
			LowerName[i] = (WCHAR)tolower(lpszInput[i]);
		LowerName[i++] = '\0';
	}

	*pOutput = LowerName;

	return TRUE;
}

// functions that put a thread in the alertable state
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

// dummy function when creating a thread in suspended state
void DummyFunction()
{
	int i = rand();
	int j = i + rand();
}