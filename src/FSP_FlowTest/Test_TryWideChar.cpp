#include "stdafx.h"

const TCHAR *pattern = _T("d:\\temp\\*.*");

octet bufferBlocks[MAX_BLOCK_SIZE * 4];

static int ParseBlock(void *buf, int32_t len);

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
#else
		wprintf_s(L"File or directory: %s\n", findFileData.cFileName);
		int nBytes = WideStringToUTF8(buffer, sizeof(buffer), findFileData.cFileName);
#endif
		//WriteTo(h, buffer, nBytes, 0, NULL);
		if (nBytes <= 0)
			continue;
		if (p + nBytes - p0 > sizeof(bufferBlocks))
			break;	// run out of buffer
		memcpy(p, buffer, nBytes);
		p += nBytes;
	} while (FindNextFile(hFind, &findFileData));
	//
	FindClose(hFind);

	//parsing the buffer
	int len = min(p - p0, MAX_BLOCK_SIZE);
	do
	{
		ParseBlock(p0, len);
		p0 += len;
		len = min(p - p0, MAX_BLOCK_SIZE);
	} while (len > 0);
}



// The iteration body that accept continuous segments of the directory list
// The 'eot' (End of Transaction) flag is to indicate the end of the list
// A reverse application layer acknowledgement message is written back to the remote end
static int ParseBlock(void *buf, int32_t len)
{
	static char partialFileName[sizeof(TCHAR) * MAX_PATH + 4];	// buffered partial file name
	static int lenPartial = 0;					// length of the partial name
	char *utf8str = (char *)buf;
	int lenCurrent = 0;
	int nScanned = 0;
	// Set the sentinel
	char c = utf8str[len - 1];
	utf8str[len - 1] = 0;
	// the first block
	if (lenPartial > 0)
	{
		while (utf8str[lenCurrent++] != 0)
			nScanned++;
		// There should be a NUL as the string terminator!
		if (c != 0 && lenCurrent >= len)
		{
			printf_s("Attack encountered? File name too long!\n");
			//clean up work here!
			return -1;
		}
		//
		memcpy(partialFileName + lenPartial, utf8str, lenCurrent);	// Make it null-terminated
#ifdef _MBCS
		char finalFileName[MAX_PATH];
		UTF8ToLocalMBCS(finalFileName, MAX_PATH, partialFileName);
		printf_s("%s\n", finalFileName);
#else
		wchar_t finalFileName[MAX_PATH];
		UTF8ToWideChars(finalFileName, MAX_PATH, partialFileName, lenPartial + lenCurrent);
		wprintf_s(L"%s\n", finalFileName);
#endif
		utf8str += lenCurrent;
		nScanned++;
		lenCurrent = 0;
		lenPartial = 0;
	}
	// A sentinel character is set before scan the input
	do
	{
		while (utf8str[lenCurrent] != 0)
			lenCurrent++, nScanned++;
		//
		if (++nScanned >= len && c != 0)
		{
			utf8str[lenCurrent] = c;
			memcpy(partialFileName, utf8str, lenCurrent);
			lenPartial = lenCurrent;
			break;
		}
		//
#ifdef _MBCS
		printf_s("%s\n", utf8str);
		//
		char finalFileName[MAX_PATH];
		UTF8ToLocalMBCS(finalFileName, MAX_PATH, utf8str);
		printf_s("%s\n", finalFileName);
#else
		wchar_t finalFileName[MAX_PATH];
		UTF8ToWideChars(finalFileName, MAX_PATH, utf8str, lenCurrent + 1);
		wprintf_s(L"%s\n", finalFileName);
#endif
		utf8str += lenCurrent + 1;
		lenCurrent = 0;
	} while (nScanned < len);
	//
	return nScanned;
}
