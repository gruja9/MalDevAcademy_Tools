#pragma once


#include <Windows.h>

#ifndef COMMON_H
#define COMMON_H




// to help identifying user input
#define UUIDFUSCATION		0x444
#define AESENCRYPTION		0x555
#define RC4ENCRYPTION		0x666
#define XORENCRYPTION		0x777
#define IPV6FUSCATION		0x111
#define IPV4FUSCATION		0x222
#define MACFUSCATION		0x333

// to help working with encryption algorithms
#define RC4KEYSIZE				16
#define XORKEYSIZE				 8

#define AESKEYSIZE				32
#define AESIVSIZE				16




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from IO.c
// read file from disk 
BOOL ReadPayloadFile(IN PBYTE FileInput, OUT PDWORD sPayloadSize, OUT PBYTE* pPayloadData);
// write file to disk
BOOL WritePayloadFile(IN PBYTE FileInput, IN DWORD sPayloadSize, IN PBYTE pPayloadData);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from StringFunctions.c
// print the decryption / deobfuscation function (as a string) to the screen
VOID PrintDecodeFunctionality(IN INT TYPE);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Encryption.c
// generate random bytes of size "sSize"
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize);
// print the input buffer as a hex char array (c syntax)
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Encryption.c
// wrapper function for InstallAesEncryption that make things easier
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize);
// do the rc4 encryption
BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);
// do the xor encryption
VOID XorEncryption(IN PBYTE pPayloadData, IN DWORD dwShellcodeSize, IN PBYTE pKey, IN DWORD dwKeySize);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Obfuscation.c
// generate the UUid output representation of the shellcode
PBYTE GenerateUuidOutput(IN PBYTE pShellcode, IN SIZE_T ShellcodeSize);
// generate the Mac output representation of the shellcode
PBYTE GenerateMacOutput(IN PBYTE pShellcode, IN SIZE_T ShellcodeSize);
// generate the ipv6 output representation of the shellcode
PBYTE GenerateIpv6Output(IN PBYTE pShellcode, IN SIZE_T ShellcodeSize);
// generate the ipv4 output representation of the shellcode
PBYTE GenerateIpv4Output(IN PBYTE pShellcode, IN SIZE_T ShellcodeSize);
char* GeneratePlainOutput(char* shellcode, int shellcodeSize);
//-------------------------------------------------------------------------------------------------------------------------------




#endif // !COMMON_H
