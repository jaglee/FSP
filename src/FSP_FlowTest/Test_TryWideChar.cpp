#include "stdafx.h"

const TCHAR *pattern = _T("d:\\temp\\*.*");

octet bufferBlocks[MAX_BLOCK_SIZE * 4];

static int ParseBlock(octet *buf, int32_t len);

void TryWideChar()
{
	char lineBuf[80];
	LocalMBCSToUTF8(bufferBlocks, sizeof(bufferBlocks), "≤‚ ‘");
	UTF8ToLocalMBCS(lineBuf, sizeof(lineBuf), (LPCSTR)bufferBlocks);
	printf_s("%s\n", lineBuf);
	//
	// streaminng into the buffer
	WIN32_FIND_DATA findFileData;
	HANDLE hFind = FindFirstFile(pattern, &findFileData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		_tprintf_s(_T("Directory is empty: %s\n"), pattern);
		return;
	}
	// Should filter out "." and ".."
	octet *p0 = bufferBlocks;
	octet *p = p0;
	do
	{
		octet buffer[MAX_PATH * 2 + 2];
#ifdef _MBCS
		printf_s("File or directory: %s\n", findFileData.cFileName);
		int nBytes = LocalMBCSToUTF8(buffer, sizeof(buffer), findFileData.cFileName);
		//
		UTF8ToLocalMBCS(lineBuf, sizeof(lineBuf), (char *)buffer);
		printf_s("Converted forth and back: %s\n", lineBuf);
		//
#else
		wprintf_s(L"File or directory: %s\n", findFileData.cFileName);
		int nBytes = WideStringToUTF8(buffer, sizeof(buffer), findFileData.cFileName);
#endif
		//WriteTo(h, buffer, nBytes, 0, NULL);
		if (nBytes <= 0)
			continue;
		//
		if (p + nBytes - p0 > sizeof(bufferBlocks))
		{
			printf_s("Run out of buffer, remaining directory entries not processed.\n");
			break;
		}
		//
		memcpy(p, buffer, nBytes);
		p += nBytes;
	} while (FindNextFile(hFind, &findFileData));
	//
	FindClose(hFind);

	//parsing the buffer
	int len = (int)min(p - p0, MAX_BLOCK_SIZE);
	do
	{
		ParseBlock(p0, len);
		p0 += len;
		len = (int)min(p - p0, MAX_BLOCK_SIZE);
	} while (len > 0);
}



static int ParseBlock(octet *utf8str, int32_t len)
{
	static char partialFileName[sizeof(TCHAR) * MAX_PATH + 4];	// buffered partial file name
	static int lenPartial = 0;					// length of the partial name
	TCHAR finalFileName[MAX_PATH];
	int lenCurrent = 0;
	int nScanned = 0;

	// Set the sentinel
	char c = utf8str[len - 1];
	utf8str[len - 1] = 0;

	// continue with previous cross-border string
	if (lenPartial > 0)
	{
		while (utf8str[lenCurrent] != 0)
		{
			lenCurrent++;
			nScanned++;
		}
		// There should be a NUL as the string terminator!
		if (c != 0 && lenCurrent >= len)
		{
			printf_s("Attack encountered? File name too long!\n");
			return -1;
		}
		//
		lenCurrent++;	// Make it null-terminated
		nScanned++;
		memcpy(partialFileName + lenPartial, utf8str, lenCurrent);
#ifdef _MBCS
		UTF8ToLocalMBCS(finalFileName, MAX_PATH, partialFileName);
		printf_s("%s\n", finalFileName);
#else
		UTF8ToWideChars(finalFileName, MAX_PATH, partialFileName, lenPartial + lenCurrent);
		wprintf_s(L"%s\n", finalFileName);
#endif
		utf8str += lenCurrent;
		lenCurrent = 0;
		lenPartial = 0;
	}
	// A sentinel character is set before scan the input
	do
	{
		while (utf8str[lenCurrent] != 0)
		{
			lenCurrent++;
			nScanned++;
		}
		//
		lenCurrent++;
		nScanned++;
		if (nScanned >= len && c != 0)
		{
			utf8str[lenCurrent - 1] = c;	// so that the sentinel character is copied
			memcpy(partialFileName, utf8str, lenCurrent);
			lenPartial = lenCurrent;
			break;
		}
		//
#ifdef _MBCS
		UTF8ToLocalMBCS(finalFileName, MAX_PATH, (char *)utf8str);
		printf_s("%s\n", finalFileName);
#else
		UTF8ToWideChars(finalFileName, MAX_PATH, (char *)utf8str, lenCurrent);
		wprintf_s(L"%s\n", finalFileName);
#endif
		utf8str += lenCurrent;
		lenCurrent = 0;
	} while (nScanned < len);
	//
	return nScanned;
}
