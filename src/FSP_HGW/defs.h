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
#include "../FSP_API.h"
#include <malloc.h>

#if defined(__WINDOWS__)

# include <WinSock2.h>
# include <mstcpip.h>
# include <io.h>
# include <share.h>

# define pthread_t	HANDLE

typedef int socklen_t;

# ifdef _MSC_VER
# pragma comment(lib, "Ws2_32.lib")
# endif


#elif defined(__linux__) || defined(__CYGWIN__)

# include <arpa/inet.h>
# include <netinet/in.h>
# include <pthread.h>
# include <sys/socket.h>
# include <sys/wait.h>
# include <termios.h>
# include <unistd.h>

# define MAX_PATH   260
# define SD_SEND	SHUT_RD
# define SD_BOTH	SHUT_RDWR
# define USHRT_MAX  0xffff        // maximum unsigned short value

# define SOCKET_ERROR   (-1)

# define closesocket	close
# define _strcmpi		strcasecmp

typedef int				SOCKET;
typedef struct sockaddr	SOCKADDR, * PSOCKADDR;
typedef struct sockaddr_in	SOCKADDR_IN, * PSOCKADDR_IN;

static inline void Sleep(int32_t millis)
{
    struct timespec tv;
    tv.tv_sec = millis / 1000;
    tv.tv_nsec = (millis % 1000) * 1000000;
    nanosleep(&tv, NULL);
}

#endif

# include <stdio.h>

#define DEFAULT_FILE		"index.html"
#define	BUFFER_POOL_SIZE	65536
#define DEFAULT_SOCKS_PORT	1080
#define HTTP_SUCCESS_HEADER	"HTTP/1.0 200 OK\r\n"

// Edge and Chrome on Windows by default use IE settings
// Firefox support both SOCKS4 and SOCKS5
// All of them does not support SOCKS4a
#define SOCKS_VERSION		4
#define SOCKS_VERSION_5		5
#define SOCKS_CMD_CONNECT	1	// only support CONNECT
#define	SOCKS_V5_AUTH_NULL 	0	// only support null authentication
#define SOCKS_V5_NO_ACCEPTABLE '\xFF'

// fine tuning this value to half number of workable hyper-thread of the platform
#define RECV_TIME_OUT		30	// half a minute
#define MAX_LEN_DOMAIN_NAME 256	// including the terminating zero!
#define MAX_NAME_LENGTH		80	// including the terminating zero!
#define MAX_PASSWORD_LENGTH	32	// not too long

enum ERepCode: octet
{
	// Error codes of SOCKS version 5 start from 'no error' (0)
	SOCKS_SERVICE_NOERROR = 0,
	SOCKS_SERVER_FAILURE,		// 1
	SOCKS_CONNECT_DISALLOWED,	// 2
	SOCKS_NETWORK_UNREACHABLE,	// 3
	SOCKS_HOST_UNREACHABLE,		// 4
	SOCKS_CONNECTION_REFUSED,	// 5
	SOCKS_TTL_EXPIRED,			// 6
	SOCKS_COMMAND_UNSUPPORTED,	// 7
	SOCKS_ADDRESS_UPSUPPORTED,	// 8
	// 'Error' codes of SOCKS version 4 are reported numbers
	REP_SUCCEEDED = 0x5A,
	REP_REJECTED = 0x5B,
	REP_NO_IDENTD = 0x5C,
	REP_AUTH_FAILED = 0x5D
};


enum EAddrType: octet
{
	ADDRTYPE_IPv4 = 1,
	ADDRTYPE_IPv6 = 4,
	ADDRTYPE_DOMAINNAME = 3
};



#pragma pack(push)
#pragma pack(1)

// SOCKSv4 tunnel request: Version(0x4), Command(0x1), DstPort(2 octets), DstIP(4 octets)
typedef struct SRequestResponse_v4
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
} *PRequestResponse_v4;



struct SRequestResponseV4a : SRequestResponse_v4
{
	char domainName[MAX_LEN_DOMAIN_NAME];
};


// Authentication method candidates, Client to Server
struct SSocksV5AuthMethodsRequest
{
	octet	version;
	uint8_t	count;
	octet	methods[255];
};



// Authentication method selected, Server to Client
struct SSocksV5AuthMethodResponse
{
	octet	version;
	octet	method;
};



typedef struct SRequestResponseV5
{
	octet	version;
	union
	{
		octet cmd;
		octet rep;
	};
	octet	_zero;		// reserved
	octet	addrType;
	union /* But of variable length! */
	{
		struct
		{
			struct in_addr inet4Addr;
			uint16_t nboPort;		// port number in network byte order
		};
		struct
		{
			uint8_t	len;
			char	txt[MAX_LEN_DOMAIN_NAME-1];
			uint16_t _place_holder_for_nboPort;
		}	domainName;
	};
} *PRequestResponseV5;



typedef struct SRequestPoolItem
{
	SOCKET			hSocket;
	int				lenReq;
	FSPHANDLE		hFSP;
	pthread_t		hThread;
	union
	{
		octet		socks_version;
		SSocksV5AuthMethodsRequest	amr;
		SSocksV5AuthMethodResponse	ans;
		SRequestResponse_v4			req;
		SRequestResponseV5			rqV5;
		SRequestResponseV4a			rqV4a;
	};
	int64_t			countTCPreceived;
	int64_t			countFSPreceived;
} *PRequestPoolItem;


#pragma pack(pop)


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

// Shared, symmetric routines
void CloseGracefully(SOCKET);
bool FSPAPI onFSPDataAvailable(FSPHANDLE, void *, int32_t, bool);
int	 FSPAPI toReadTCPData(FSPHANDLE, void *, int32_t);
