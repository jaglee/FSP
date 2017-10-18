/*
 * Common class definitions for implementing FSP http accelerator, SOCKS gateway and tunnel server
 *
    Copyright (c) 2017, Jason Gao
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

#ifdef WIN32
#include <WinSock2.h>
#include <mstcpip.h>
#include <MSWSock.h>
#include "../FSP_API.h"
#include "../Crypto/CryptoStub.h"
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <strings.h>
#include <pthread.h>
#include <sys/wait.h>
#define _strcmpi strcasecmp
#endif

#include "../FSP_API.h"
#include "../Crypto/CryptoStub.h"

#define DEFAULT_FILE	"index.html"
#define	BUFFER_POOL_SIZE 65536
#define DEFAULT_SOCKS_PORT 1080

// Edge and Chrome on Windows by default use IE settings
// Firefox support both SOCKS4 and SOCKS5
// All of them does not support SOCKS4a
#define SOCKS_VERSION		4
#define SOCKS_CMD_CONNECT	1	// only support CONNECT
#define MAX_WORKING_THREADS	40
// fine tuning this value to half number of workable hyper-thread of the platform
#define RECV_TIME_OUT		30	// half a miniute


enum ERepCode: octet
{
	REP_SUCCEEDED = 0x5A,
	REP_REJECTED = 0x5B,
	REP_NO_IDENTD = 0x5C,
	REP_AUTH_FAILED = 0x5D
};


#include <pshpack1.h>

typedef struct SRequestResponse
{
	union
	{
		octet version;	// for request
		octet _reserved;// for response
	};
	union
	{
		octet cmd;
		octet rep;
	};
	uint16_t nboPort;	// port number in network byte order
	in_addr inet4Addr;
	// char	userId[2];	// just a placeholder
} *PRequestResponse;

// SOCKSv4 tunnel request: Version(0x4), Command(0x1), DstPort(2 octets), DstIP(4 octets)



typedef struct SRequestPoolItem
{
	SOCKET			hSocket;
	FSPHANDLE		hFSP;
	union
	{
		SRequestResponse req;
		void * $data_req;
	};
} *PRequestPoolItem;


#include <poppack.h>


class RequestPool
{
	PRequestPoolItem items;
	int			capacity;
public:
	bool Init(int);
	// assume every instance is declared static
	~RequestPool() { if(capacity > 0) free(items); }
	//
	PRequestPoolItem AllocItem(FSPHANDLE);
	PRequestPoolItem AllocItem();
	PRequestPoolItem FindItem(FSPHANDLE);
	bool FreeItem(PRequestPoolItem);
};

extern RequestPool requestPool;

// Client-to SOCKS4 service interface
void ReportErrorToClient(SOCKET, ERepCode);
void CloseClient(SOCKET, bool);

// Server side forward declarations
int	FSPAPI onMultiplying(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);
void ReportToRemoteClient(PRequestPoolItem, ERepCode);

// Shared, symmetric routines
bool FSPAPI onFSPDataAvailable(FSPHANDLE, void *, int32_t, bool);
int	 FSPAPI toReadTCPData(FSPHANDLE, void *, int32_t);
