/**
 * Used to be a short module in FileSyncClient, now in FSP_FlowTest
 * which meant to check that the memory pattern saved in the designated file is right
 */
#include "stdafx.h"
#include "tchar.h"

// "$memory.^";
int CompareMemoryPattern(TCHAR *fileName)
{
	static	uint8_t	buf[0x20000];	// 128KB

	int fd;
	errno_t	err = _tsopen_s(& fd
			, fileName
			, _O_BINARY | _O_RDONLY | _O_SEQUENTIAL
			, _SH_DENYWR
			, 0);
	if(err != 0)
	{
		_tprintf_s(_T("Error number = %d: cannot open file %s\n"), err, fileName);
		return -2;
	}

	_tprintf_s(_T("To check word pattern in %s\n"), fileName);

	int bytesRead = _read(fd, buf, sizeof(buf));
	_close(fd);
	if(bytesRead < 0)
		return bytesRead;
	if((bytesRead & (sizeof(uint32_t) - 1)) != 0)
		return -EDOM;

	for(register int i = 0; i < int(bytesRead / sizeof(uint32_t)); i++)
	{
		if(* (uint32_t *) & buf[i * sizeof(uint32_t)] != htobe32(i))
			__debugbreak();
	}

	_tprintf_s(_T("Word pattern in %s was checked.\n"), fileName);

	return 0;
}
