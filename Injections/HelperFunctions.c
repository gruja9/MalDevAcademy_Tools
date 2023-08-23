#include <windows.h>

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