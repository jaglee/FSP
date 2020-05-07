/*
 * FSP lower-layer service program, the entry point, the top-level control,
 * AND the security related issues.
 * Platform-dependent / IPC-mechanism-dependent
 * Garbage Collection is treated as a security-related issue.
 * The FSP Finite State Machine is split across command.cpp, remote.cpp and timers.cpp
 *
    Copyright (c) 2012, Jason Gao
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    - Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT,INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
 */

#include "fsp_srv.h"

#if defined(__WINDOWS__)
# define AF_FOR_IPC			AF_INET
# define CLOSE_IPC			closesocket
# define SOCKADDR_FOR_IPC	struct sockaddr_in
#elif defined(__linux__) || defined(__CYGWIN__)
# include <netinet/tcp.h>
# include <sys/un.h>
# define AF_FOR_IPC			AF_UNIX
# define CLOSE_IPC			close
# define SOCKADDR_FOR_IPC	struct sockaddr_un
#endif

 // The singleton instance of the connect request queue
ConnectRequestQueue ConnectRequestQueue::requests;

// The singleton instance of the lower service interface 
CLowerInterface	CLowerInterface::Singleton;

extern "C"
int main(int argc, char * argv[])
{
	SOCKADDR_FOR_IPC addr;
	int sd;

	if(!CLowerInterface::Singleton.Initialize())
	{
		REPORT_ERRMSG_ON_TRACE("Cannot access lower interface in main(), aborted.");
		exit(-1);
	}

	sd = socket(AF_FOR_IPC, SOCK_STREAM, 0);
	if (sd < 0)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot create the socket for listening ULA's command");
		exit(-1);
	}

#if defined(__WINDOWS__)
	addr.sin_family = AF_FOR_IPC;
	addr.sin_port = htobe16(DEFAULT_FSP_UDPPORT);
	addr.sin_addr.S_un.S_addr = IN4ADDR_LOOPBACK;
	memset(addr.sin_zero, 0, sizeof(addr.sin_zero));
	if (bind(sd, (struct sockaddr*) & addr, sizeof(SOCKADDR_FOR_IPC)) < 0)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot bind the command-stream socket to the loop-back address.");
		exit(-1);
	}
#elif defined(__linux__) || defined(__CYGWIN__)
	addr.sun_family = AF_FOR_IPC;
	strncpy(addr.sun_path, SERVICE_SOCKET_PATH, sizeof(addr.sun_path) - 1);
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
	if (bind(sd, (struct sockaddr*)&addr, sizeof(SOCKADDR_FOR_IPC)) < 0)
	{
		int r = 0;
		if(errno == EADDRINUSE)
		{
			if(unlink(addr.sun_path) < 0)
				printf("%s existed but cannot be unlinked.\n", addr.sun_path);
			r = bind(sd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));
			if(r == 0)
				printf("%s existed but was unlinked and re-bound.\n", addr.sun_path);
		}
		if(r < 0)
		{
			perror("Cannot bind the AF_UNIX socket to the designated path");
			exit(-1);
		}
	}
#endif
	// If the backlog argument is greater than the value in /proc/sys/net/core/somaxconn,
	// then it is silently truncated to that value; the default value in this file is 128
	if (listen(sd, MAX_CONNECTION_NUM) != 0)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot set the listening queue to accept ULA's command.");
		exit(-1);
	}

	try
	{
		socklen_t szAddr = sizeof(SOCKADDR_FOR_IPC);
		SOCKADDR_FOR_IPC addrIn;
		int sdNew;
		while ((sdNew = accept(sd, (struct sockaddr*) & addrIn, &szAddr)) != -1)
		{
			DWORD optval = 1;
			setsockopt(sdNew, IPPROTO_TCP, TCP_NODELAY, (const char*)&optval, sizeof(optval));

			if (!CLowerInterface::Singleton.AddULAChannel(sdNew))
				CLOSE_IPC(sdNew);
		}
		REPORT_ERRMSG_ON_TRACE("Command channel broken.");
	}
	catch (...)
	{
		BREAK_ON_DEBUG();
		CLowerInterface::Singleton.Destroy();
	}

	exit(0);
}
