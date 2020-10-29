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


 // The singleton instance of the connect request queue
ConnectRequestQueue ConnectRequestQueue::requests;

// The singleton instance of the lower service interface 
CLowerInterface	CLowerInterface::Singleton;


int WaitForULACommand();

extern "C"
int main(int argc, char * argv[])
{
	if(!CLowerInterface::Singleton.Initialize())
	{
		REPORT_ERRMSG_ON_TRACE("Cannot access lower interface in main(), aborted.");
		exit(-1);
	}

#if defined(__WINDOWS__)
	try
	{
		exit(WaitForULACommand());
	}
#elif defined(__linux__) || defined(__CYGWIN__)
# ifdef __linux__
#  include <linux/un.h>
# else
#  include <sys/un.h>
# endif
	struct sockaddr_un addr;
	int sd;

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd < 0)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot create the socket for listening ULA's command");
		exit(-1);
	}

	bzero(&addr, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SERVICE_SOCKET_PATH, sizeof(addr.sun_path) - 1);
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
	if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		int r = 0;
		if(errno == EADDRINUSE)
		{
			if(unlink(addr.sun_path) < 0)
				printf("%s existed but cannot be unlinked.\n", addr.sun_path);
			r = bind(sd, (struct sockaddr *)&addr, sizeof(addr));
			if(r == 0)
				printf("%s existed but was unlinked and re-bound.\n", addr.sun_path);
		}
		if(r < 0)
		{
			perror("Cannot bind the AF_UNIX socket to the designated path");
			exit(-1);
		}
	}
	//
	if (listen(sd, 5) != 0)
	{
		REPORT_ERRMSG_ON_TRACE("Cannot set the listening queue to accept ULA's command.");
		exit(-1);
	}

	try
	{
		struct sockaddr_un addrPeer;
		int sdNew;
		socklen_t szAddr = sizeof(addrPeer);
		while ((sdNew = accept(sd, (sockaddr *)&addrPeer, &szAddr)) != -1)
		{
#ifdef TRACE
			printf("Peer's socket address: %s\n", addrPeer.sun_path);
#endif
			if (!CLowerInterface::Singleton.AddULAChannel(sdNew))
				close(sdNew);
			szAddr = sizeof(addrPeer);
		}
		REPORT_ERRMSG_ON_TRACE("Command channel broken.");
	}
#endif
	catch (...)
	{
		BREAK_ON_DEBUG();
		CLowerInterface::Singleton.Destroy();
	}

	exit(0);
}
