// FSP_IPv6Preconfig.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


// mobility support is the main of FSP key features
static class CIfConfiguror
{
private:
	static const int READ_FD = 0;
	static const int WRITE_FD = 1;
	static const int size_pipe_buf = 512;
	int fdStdInPipe[2];
	int fdStdOutPipe[2];
	HANDLE hProcess;	// the handle of the process that to configure addresses  

protected:
	CIfConfiguror();
	~CIfConfiguror();
	int LOCALAPI SetAddress(PIN6_ADDR, DWORD);
	int LOCALAPI RemoveAddress(PIN6_ADDR, DWORD);

	friend class CLowerInterface;
} * pConfiguror;


int _tmain(int argc, _TCHAR* argv[])
{
	pConfiguror = new CIfConfiguror();
	//...
	delete pConfiguror;

	//pConfiguror = new CIfConfiguror();
	//// exploit the side-effect of learn address to do house-keeping:
	//// unregister all session-ary IPv6 addresses
	//LearnAddresses();
	//delete pConfiguror;

	return 0;
}






// return the handle of the process that config ipv6 address
CIfConfiguror::CIfConfiguror()
{
	///*
	int fdStdIn;
	int fdStdOut;
	const char * strCommand;
	char strResponse[size_pipe_buf];
	int nExitCode = STILL_ACTIVE;

	time_t t0 = time(NULL);
	srand((unsigned int)t0);

	// Create the pipe
	if(_pipe(fdStdInPipe, size_pipe_buf, O_NOINHERIT) == -1)
		throw E_HANDLE;

	if(_pipe(fdStdOutPipe, size_pipe_buf, O_NOINHERIT) == -1)
		goto l_bailout;

	// Duplicate stdout file descriptor (next line will close original)
	fdStdIn = _dup(_fileno(stdin));
	fdStdOut = _dup(_fileno(stdout));

	// Duplicate read end of pipe to stdin file descriptor
	if(_dup2(fdStdInPipe[READ_FD], _fileno(stdin)) != 0)
	{
		TRACE_HERE("Cannot redirect stdin of the child process.\n");
		goto l_bailout2;
	}

	// Duplicate write end of pipe to stdout file descriptor
	if(_dup2(fdStdOutPipe[WRITE_FD], _fileno(stdout)) != 0)
	{
		TRACE_HERE("Cannot redirect stdout of the child process.\n");
		goto l_bailout2;
	}

	// Close original read end of pipe
	_close(fdStdInPipe[READ_FD]);
	// close original write end of pipe
	_close(fdStdOutPipe[WRITE_FD]);

	// Spawn process, assume the default windows root directory
	// TODO: UNRESOLVED! how to avoid man-in-the-middle attack if taking use of PATH variable?
	hProcess = (HANDLE)_spawnl(_P_NOWAIT, "c:\\windows\\system32\\netsh.exe", "netsh", NULL);
	if(hProcess == NULL)
		throw E_HANDLE;	// E_ASYNC_OPERATION_NOT_STARTED;

	// Duplicate copy of original stdin back into stdin
	if(_dup2(fdStdIn, _fileno(stdin)) != 0)
	{
		TRACE_HERE("Fatal! Cannot recover stdin of the parent process.\n");
		// SHALL exit instantly
		throw E_HANDLE;
	}

	// Duplicate copy of original stdout back into stdout
	if(_dup2(fdStdOut, _fileno(stdout)) != 0)
	{
		TRACE_HERE("Fatal! Cannot recover stdout of the parent process.\n");
		// SHALL exit instantly
		throw E_HANDLE;
	}

	// Close duplicate copy of original stdin & stdout
	_close(fdStdIn);
	_close(fdStdOut);

	GetExitCodeProcess(hProcess, (unsigned long*)&nExitCode);
	if(nExitCode == STILL_ACTIVE)
    {
		strCommand = "interface ipv6\r\n";
		_write(fdStdInPipe[WRITE_FD], strCommand, (unsigned int)strlen(strCommand));
		_read(fdStdOutPipe[READ_FD], strResponse, size_pipe_buf);
    }
	return;

l_bailout2:
	_close(fdStdOutPipe[READ_FD]);
	_close(fdStdOutPipe[WRITE_FD]);

l_bailout:
	_close(fdStdInPipe[READ_FD]);
	_close(fdStdInPipe[WRITE_FD]);
	throw E_ABORT;
	// */
}



CIfConfiguror::~CIfConfiguror()
{
	///*
	// kill the process for configuring the addresses
	TerminateProcess(hProcess, 0);
	// release the pipe handle
	_close(fdStdOutPipe[READ_FD]);
	_close(fdStdInPipe[WRITE_FD]);
	// */
}



int LOCALAPI CIfConfiguror::SetAddress(PIN6_ADDR pAddr, DWORD idxIf)
{
#if !(WINVER < 0x0600)
	///*
	char strResponse[size_pipe_buf + 4];
	char strbuf[80];
	size_t nPrefix;
	char *s;

	strcpy_s((char *)strbuf, sizeof(strbuf), "add address ");
	// the interfacer number
	nPrefix = strlen(strbuf);
	s = & strbuf[nPrefix];
	_itoa_s(idxIf, s, sizeof(strbuf) - nPrefix, 10);
	nPrefix += strlen(s);
	strbuf[nPrefix++] = ' ';

	s = RtlIpv6AddressToString(pAddr, & strbuf[nPrefix]);	// pointer to the NUL terminator
	s[0] = '\r'; s[1] = '\n'; s[2] = 0;

	_write(fdStdInPipe[WRITE_FD], strbuf, (unsigned int)strlen(strbuf));
	_read(fdStdOutPipe[READ_FD], strResponse, size_pipe_buf);

	// TODO: UNRESOLVED! parse the response and set the returned value
	// */
	return 0;
#else
	return -1;
#endif
}



int LOCALAPI CIfConfiguror::RemoveAddress(PIN6_ADDR pAddr, DWORD idxIf)
{
#if !(WINVER < 0x0600)
	///*
	char strResponse[size_pipe_buf + 4];
	char strbuf[80];
	size_t nPrefix;
	char *s;

	strcpy_s((char *)strbuf, sizeof(strbuf), "delete address ");
	// the interfacer number
	nPrefix = strlen(strbuf);
	s = & strbuf[nPrefix];
	_itoa_s(idxIf, s, sizeof(strbuf) - nPrefix, 10);
	nPrefix += strlen(s);
	strbuf[nPrefix++] = ' ';

	s = RtlIpv6AddressToString(pAddr, & strbuf[nPrefix]);	// pointer to the NUL terminator
	s[0] = '\r'; s[1] = '\n'; s[2] = 0;

	_write(fdStdInPipe[WRITE_FD], strbuf, (unsigned int)strlen(strbuf));
	_read(fdStdOutPipe[READ_FD], strResponse, size_pipe_buf);

	// TODO: UNRESOLVED! parse the response and set the returned value
	// */
	return 0;
#else
	return -1;
#endif
}

