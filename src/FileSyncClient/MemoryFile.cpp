#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <io.h>
#include <errno.h>
#include <fcntl.h>
#include <share.h>
#include "../FSP_API.h"


// "$memory.^";
int CompareMemoryPattern(char *fileName)
{
	static	uint8_t	buf[0x20000];	// 128KB

	int fd;
	errno_t	err = _sopen_s(& fd
			, fileName
			, _O_BINARY | _O_RDONLY | _O_SEQUENTIAL
			, _SH_DENYWR
			, 0);
	if(err != 0)
	{
		printf_s("Error number = %d: cannot open file %s\n", err, fileName);
		return -2;
	}

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

	return 0;
}