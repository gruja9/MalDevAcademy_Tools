#include <Windows.h>
#include <stdio.h>

#include "Common.h"


char* GenerateUUid(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	char Output0[32], Output1[32], Output2[32], Output3[32];
	char result[128]; // 32 * 4

	// generating output0 from the first 4 bytes
	sprintf(Output0, "%0.2X%0.2X%0.2X%0.2X", d, c, b, a);

	// generating output1 from the second 4 bytes
	sprintf(Output1, "%0.2X%0.2X-%0.2X%0.2X", f, e, h, g);

	// generating output2 from the third 4 bytes
	sprintf(Output2, "%0.2X%0.2X-%0.2X%0.2X", i, j, k, l);

	// generating output3 from the last 4 bytes
	sprintf(Output3, "%0.2X%0.2X%0.2X%0.2X", m, n, o, p);

	// combining Output0,1,2,3 all together to generate our output to return
	sprintf(result, "%s-%s-%s%s", Output0, Output1, Output2, Output3);

	//printf("[i] result: %s\n", (char*)result);
	return (char*)result;
}




// generate the UUid output representation of the shellcode
PBYTE GenerateUuidOutput(IN PBYTE pShellcode, IN SIZE_T ShellcodeSize) {

	BYTE output[4500];
	PBYTE pOutput = output;

	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0) {
		return NULL;
	}

	pOutput += sprintf(pOutput, "int main()\n{\n");
	pOutput += sprintf(pOutput, "char* UuidArray[%d] = { \n\t", ShellcodeSize/16);
	// c is 16 so that we start at the first 16 bytes (check later comments to understand)
	int c = 16, C = 0;
	char* IP = NULL;
	for (int i = 0; i < ShellcodeSize; i++) {
		// tracking the bytes read, at each 16 bytes (when c is 16), we enter this if statement, to generate our ipv6 address
		if (c == 16) {
			C++;
			// generating our uuid address, from 16 bytes that starts at i and count 15 bytes more ... 
			IP = GenerateUUid(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);

			if (i == ShellcodeSize - 16) {
				// printing the last uuid address
				pOutput += sprintf(pOutput, "\"%s\"", IP);
				break;
			}
			else {
				// printing the uuid address
				pOutput += sprintf(pOutput, "\"%s\", ", IP);
			}
			c = 1;
			// just to track how many uuid addresses we printed, so that we print \n\t and make the output more clean
			if (C % 3 == 0) {
				pOutput += sprintf(pOutput, "\n\t");
			}
		}
		else {
			c++;
		}
	}

	pOutput += sprintf(pOutput, "\n};\nint UuidArrayElements = %d;\n\n", ShellcodeSize/16);
	pOutput += sprintf(pOutput, "PVOID pShellcode = NULL; DWORD sShellcodeSize = NULL;\nUuidDeobfuscation(UuidArray, UuidArrayElements, &pShellcode, &sShellcodeSize);\n");
	pOutput += sprintf(pOutput, "HeapFree(GetProcessHeap(), 0, pShellcode);\n\nreturn 0;\n}");

	return output;
}


char* GenerateByte(int byte)
{
	char Output[4];
	sprintf(Output, "\\x%1.2x", (unsigned)(unsigned char)byte);
	return (char*)Output;
}

char* GeneratePlainOutput(char* shellcode, int shellcodeSize)
{
	char Output[4500];
	char *pOutput = Output, *Byte = NULL;

	// if null
	if (shellcode == NULL || shellcodeSize == NULL)
		return NULL;

	pOutput += sprintf(pOutput, "int main()\n{\n");
	pOutput += sprintf(pOutput, "char* PlainArray [%d] =\n\t\"", shellcodeSize);
	for (int i = 0; i < shellcodeSize; i++)
	{
		Byte = GenerateByte(shellcode[i]);
		pOutput += sprintf(pOutput, "%s", Byte);

		if (i != 0 && (i+1) % 16 == 0)
			pOutput += sprintf(pOutput, "\"\n\t\"");
	}
	pOutput += sprintf(pOutput, "\";\n");
	pOutput += sprintf(pOutput, "int PlainArraySize = %d;\n\nreturn 0;\n}", shellcodeSize);

	return (char*)Output;
}


// taking input raw bytes and returning them in mac string format
char* GenerateMAC(int a, int b, int c, int d, int e, int f) {
	char Output[64];
	sprintf(Output, "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X", a, b, c, d, e, f);
	//	printf("[i] Output: %s\n", Output);
	return (char*)Output;
}

// generate the Mac output representation of the shellcode
PBYTE GenerateMacOutput(IN PBYTE pShellcode, IN SIZE_T ShellcodeSize) {

	BYTE output[4500];
	PBYTE pOutput = output;

	// if null or the size is not multiple of 6
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 6 != 0) {
		return NULL;
	}

	pOutput += sprintf(pOutput, "int main()\n{\n");
	pOutput += sprintf(pOutput, "char* MacArray [%d] = {\n\t", ShellcodeSize/6);
	// c is 6 so that we start at the first 6 bytes (check later comments to understand)
	int c = 6, C = 0;
	char* Mac = NULL;
	for (int i = 0; i < ShellcodeSize; i++) {
		// tracking the bytes read, at each 6 bytes (when c is 46, we enter this if statement, to generate our Mac address
		if (c == 6) {
			C++;
			// generating our Mac address, from a 6 bytes that starts at i and count 5 bytes more ...
			Mac = GenerateMAC(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3], pShellcode[i + 4], pShellcode[i + 5]);
			if (i == ShellcodeSize - 6) {
				// printing the last Mac address
				pOutput += sprintf(pOutput, "\"%s\"", Mac);
				break;
			}
			else {
				// printing the Mac address
				pOutput += sprintf(pOutput, "\"%s\", ", Mac);
			}
			c = 1;
			// just to track how many ipv4 addresses we printed, so that we print \n\t and make the output more clean
			if (C % 6 == 0) {
				pOutput += sprintf(pOutput, "\n\t");
			}
		}
		else {
			c++;
		}
	}
	pOutput += sprintf(pOutput, "\n};\nint MacArrayElements = %d;\n\n", ShellcodeSize/6);
	pOutput += sprintf(pOutput, "PVOID pShellcode = NULL; DWORD sShellcodeSize = NULL; \n\nMacDeobfuscation(MacArray, MacArrayElements, &pShellcode, &sShellcodeSize);\n\n");
	pOutput += sprintf(pOutput, "HeapFree(GetProcessHeap(), 0, pShellcode);\n\nreturn 0;\n}");

	return (PBYTE)output;
}




// taking input raw bytes and returning them in ipv6 string format
char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	char Output0[32], Output1[32], Output2[32], Output3[32];

	char result[128]; // 32 * 4
	// generating output0 from the first 4 bytes
	sprintf(Output0, "%0.2X%0.2X:%0.2X%0.2X", a, b, c, d);

	// generating output1 from the second 4 bytes
	sprintf(Output1, "%0.2X%0.2X:%0.2X%0.2X", e, f, g, h);

	// generating output2 from the third 4 bytes
	sprintf(Output2, "%0.2X%0.2X:%0.2X%0.2X", i, j, k, l);

	// generating output3 from the last 4 bytes
	sprintf(Output3, "%0.2X%0.2X:%0.2X%0.2X", m, n, o, p);

	// combining Output0,1,2,3 all together to generate our output to return
	sprintf(result, "%s:%s:%s:%s", Output0, Output1, Output2, Output3);

	//printf("[i] result: %s\n", (char*)result);

	return (char*)result;

}


// generate the ipv6 output representation of the shellcode
PBYTE GenerateIpv6Output(IN PBYTE pShellcode, IN SIZE_T ShellcodeSize) {

	BYTE output[4500];
	PBYTE pOutput = output;

	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0) {
		return NULL;
	}

	pOutput += sprintf(pOutput, "int main()\n{\n");
	pOutput += sprintf(pOutput, "char* Ipv6Array [%d] = { \n\t", ShellcodeSize/16);
	// c is 16 so that we start at the first 16 bytes (check later comments to understand)
	int c = 16, C = 0;
	char* IP = NULL;
	for (int i = 0; i < ShellcodeSize; i++) {
		// tracking the bytes read, at each 16 bytes (when c is 16), we enter this if statement, to generate our ipv6 address
		if (c == 16) {
			C++;
			// generating our ipv6 address, from 16 bytes that starts at i and count 15 bytes more ... 
			IP = GenerateIpv6(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);

			if (i == ShellcodeSize - 16) {
				// printing the last ipv6 address
				pOutput += sprintf(pOutput, "\"%s\"", IP);
				break;
			}
			else {
				// printing the ipv6 address
				pOutput += sprintf(pOutput, "\"%s\", ", IP);
			}
			c = 1;
			// just to track how many ipv6 addresses we printed, so that we print \n\t and make the output more clean
			if (C % 3 == 0) {
				pOutput += sprintf(pOutput, "\n\t");
			}
		}
		else {
			c++;
		}
	}

	pOutput += sprintf(pOutput, "\n};\nint Ipv6ArrayElements = %d;\n\n", ShellcodeSize/16);
	pOutput += sprintf(pOutput, "PVOID pShellcode = NULL; DWORD sShellcodeSize = NULL;\nIpv6Deobfuscation(Ipv6Array, Ipv6ArrayElements, &pShellcode, &sShellcodeSize);\n\n");
	pOutput += sprintf(pOutput, "HeapFree(GetProcessHeap(), 0, pShellcode);\n\nreturn 0;\n}");

	return output;
}




// taking input raw bytes and returning them in ipv4 string format
char* GenerateIpv4(int a, int b, int c, int d) {

	unsigned char Output[32];
	// combining all to *Output* to return 
	sprintf(Output, "%d.%d.%d.%d", a, b, c, d);
	//printf("[i] Output: %s\n", Output);

	return (char*)Output;
}


// generate the ipv4 output representation of the shellcode
PBYTE GenerateIpv4Output(IN PBYTE pShellcode, IN SIZE_T ShellcodeSize) {

	BYTE output[4500];
	PBYTE pOutput = output;

	// if null or the size is not multiple of 4
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 4 != 0) {
		return NULL;
	}

	pOutput += sprintf(pOutput, "int main()\n{\n");
	pOutput += sprintf(pOutput, "char* Ipv4Array[%d] = { \n\t", ShellcodeSize/4);
	// c is 4 so that we start at the first 4 bytes (check later comments to understand)
	int c = 4, C = 0;
	char* IP = NULL;
	for (int i = 0; i < ShellcodeSize; i++) {
		// tracking the bytes read, at each 4 bytes (when c is 4), we enter this if statement, to generate our ipv4 address
		if (c == 4) {
			C++;
			// generating our ipv4 address, from a 4 bytes that starts at i and count 3 bytes more ... 
			IP = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);
			if (i == ShellcodeSize - 4) {
				// printing the last ipv4 address
				pOutput += sprintf(pOutput, "\"%s\"", IP);
				break;
			}
			else {
				// printing the ipv4 address
				pOutput += sprintf(pOutput, "\"%s\", ", IP);
			}
			c = 1;
			// just to track how many ipv4 addresses we printed, so that we print \n\t and make the output more clean
			if (C % 8 == 0) {
				pOutput += sprintf(pOutput, "\n\t");
			}
		}
		else {
			c++;
		}
	}
	pOutput += sprintf(pOutput, "\n};\nint Ipv4ArrayElements = %d;\n\n", ShellcodeSize/4);
	pOutput += sprintf(pOutput, "PVOID pShellcode = NULL; DWORD sShellcodeSize = NULL;\n\nIpv4Deobfuscation(Ipv4Array, Ipv4ArrayElements, &pShellcode, &sShellcodeSize);\n\n");
	pOutput += sprintf(pOutput, "HeapFree(GetProcessHeap(), 0, pShellcode);\n\nreturn 0;\n}");

	return output;
}
