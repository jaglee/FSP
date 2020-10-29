// TestHGW.cpp : Defines the entry point for the console application.
// This program is a mixed test of FSP http and socks gateway server
#include <assert.h>
#include <memory.h>
#include "../FSP_HGW/defs.h"

static int	SpawnOneConnection();
static int	PressureTest();
extern bool unit_test();

#if defined(__WINDOWS__)

int main()
{
	WSADATA wsaData;
	int r = 0;
	if(! unit_test())
		return -1;

	if (WSAStartup(0x202, &wsaData) < 0)
	{
		printf_s("Cannot start up Windows socket service provider.\n");
		return -1;
	}

	//r = SpawnOneConnection();
	//if(r < 0)
	//	printf_s("Failed with error: %d\n", WSAGetLastError());

	PressureTest();

	WSACleanup();

	return r;
}

#elif defined(__linux__) || defined(__CYGWIN__)

#define printf_s printf

static int unit_test_atomic();

int main()
{
	if(unit_test_atomic() != 0)
		return -1;

	if(! unit_test())
		return -1;

	int r = SpawnOneConnection();
	if(r < 0)
	{
		printf_s("The routine returned %d, ", r);
		perror("test failed:");
	}
	PressureTest();
	return r;
}

#endif


static int SpawnOneConnection()
{
	SOCKET h = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (h == SOCKET_ERROR)
		return -1;

	sockaddr_in remoteEnd;
#if defined(__WINDOWS__)
	remoteEnd.sin_addr.S_un.S_addr = IN4ADDR_LOOPBACK;
#elif defined(__linux__) || defined(__CYGWIN__)
	remoteEnd.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
#endif

	remoteEnd.sin_family = AF_INET;
	remoteEnd.sin_port = htons(1080);
	memset(remoteEnd.sin_zero, 0, sizeof(remoteEnd.sin_zero));

	int r = connect(h, (sockaddr*)&remoteEnd, sizeof(sockaddr_in));
	if (r == SOCKET_ERROR)
	{
l_bailout:
		closesocket(h);
		return r;
	}

	// char request[] = "\x04\x01\0\x50\x7F\000\000\001Sciter"; // 127.0.0.1:80
	// char request[] = "\x04\x01\0\x50\xC0\xA8\x09\x71Sciter";	// 192.168.9.113:80
	char request[]  =	"\x04\x01\0\x50\x7D\x27\x34\x1ASciter";	// http://news.qq.com:80 125.39.52.26:80
	r = send(h, request, sizeof(request), 0);
	if (r == SOCKET_ERROR)
		goto l_bailout;

	printf_s("\n%d bytes sent for SOCKS CONNECT\n", r);

	char buf[8];	// what expected is 8 bytes SOCKS v4 response
	r = recv(h, buf, sizeof(buf), 0);
	if (r == SOCKET_ERROR)
		goto l_bailout;

	if (buf[1] != 90)
	{
		printf_s("Connect request rejected.\n");
		r = -1;
		goto l_bailout;
	}

	char getURI[] = "GET / HTTP/1.1\r\n"
		"Accept: text/html, application/xhtml+xml, image/jxr\r\n"
		"Accept-Encoding: gzip, deflate\r\n"
		"Accept-Language: en-US, en; q=0.8, zh-Hans-CN; q=0.5, zh-Hans; q=0.3\n"
		"DNT: 1\r\n"
		"Host: news.qq.com\r\n"
		"User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)\r\n"
		"\r\n";
	r = send(h, getURI, (int)strlen(getURI), 0);
	if (r == SOCKET_ERROR)
		goto l_bailout;

	printf_s("\n%d bytes sent for HTTP request\n", r);

	static char largeBuf[0x100000];	// 1MB
	r = recv(h, largeBuf, sizeof(largeBuf), 0);
	if (r > 0)
		printf_s("\r\n\n%d octets received:\r\n\n%s", r, largeBuf);
	else if (r == SOCKET_ERROR)
		goto l_bailout;

	shutdown(h, SD_BOTH);
	closesocket(h);
	// Or else 10056, socket already connected

	h = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	// Or else 10038, not a socket
	if (h == SOCKET_ERROR)
		return -1;

	r = connect(h, (sockaddr*)&remoteEnd, sizeof(sockaddr_in));
	if (r == SOCKET_ERROR)
		goto l_bailout;

	char request1[] = "\x04\x01\x0B\x1B\x7D\x27\x34\x1A";			// An erroneous request
	r = send(h, request1, sizeof(request1), 0);
	if (r == SOCKET_ERROR)
		goto l_bailout;

	printf_s("\n%d bytes sent for SOCKS CONNECT(unknown port)\n", r);

	r = recv(h, buf, sizeof(buf), 0);
	if (r == SOCKET_ERROR)
		goto l_bailout;

	if (buf[1] == 90)
	{
		printf_s("Connect request shall be rejected!\n");
		r = -1;
		goto l_bailout;
	}
	printf_s("The connection is rejected, SOCKSv4 return code = %d\n", buf[1]);

	shutdown(h, SD_BOTH);
	closesocket(h);

	h = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (h == SOCKET_ERROR)
		return -1;

	r = connect(h, (sockaddr*)&remoteEnd, sizeof(sockaddr_in));
	if (r == SOCKET_ERROR)
		goto l_bailout;

	// redirect:
	char request2[] = "\x04\x01\x01\xBB\x7D\x27\x34\x1ASciter";	// https://news.qq.com:443
	r = send(h, request2, sizeof(request2), 0);
	if (r == SOCKET_ERROR)
		goto l_bailout;

	printf_s("\n%d bytes sent for SOCKS CONNECT(https)\n", r);
	r = recv(h, buf, sizeof(buf), 0);
	if (r == SOCKET_ERROR)
		goto l_bailout;

	if (buf[1] != 90)
	{
		printf_s("Connect request for https rejected.\n");
		r = -1;
		goto l_bailout;
	}

	r = send(h, getURI, (int)strlen(getURI), 0);	// Should have made a https hello request
	if (r == SOCKET_ERROR)
		goto l_bailout;

	printf_s("\n%d bytes sent for HTTP request\n", r);

	r = recv(h, largeBuf, sizeof(largeBuf), 0);
	if (r > 0)
	{
		printf_s("\r\n\n%d\r\n\n%s", r, largeBuf);
		r = 0;
	}

	shutdown(h, SD_BOTH);
	goto l_bailout;
}



static int PressureTest()
{
	static char largeBuf[0x100000];	// 1MB
	sockaddr_in remoteEnd;
#if defined(__WINDOWS__)
	remoteEnd.sin_addr.S_un.S_addr = IN4ADDR_LOOPBACK;
#elif defined(__linux__) || defined(__CYGWIN__)
	remoteEnd.sin_addr.s_addr = htobe32(INADDR_LOOPBACK);
#endif

	remoteEnd.sin_family = AF_INET;
	remoteEnd.sin_port = htons(1080);
	memset(remoteEnd.sin_zero, 0, sizeof(remoteEnd.sin_zero));

	int round = 1;
	SOCKET h;
	while ((h = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != SOCKET_ERROR)
	{
		int r = connect(h, (sockaddr*)&remoteEnd, sizeof(sockaddr_in));
		if (r == SOCKET_ERROR)
			break;

		char request[] = "\x04\x01\0\x50\x7D\x27\x34\x1ASciter";	// http://news.qq.com:80 125.39.52.26:80
		r = send(h, request, sizeof(request), 0);
		if (r == SOCKET_ERROR)
			break;

		printf_s("\nRound#%d %d bytes sent for SOCKS CONNECT\n", round, r);

		char buf[8];	// what expected is 8 bytes SOCKS v4 response
		r = recv(h, buf, sizeof(buf), 0);
		if (r == SOCKET_ERROR)
			break;

		if (buf[1] != 90)
		{
			printf_s("Connect request rejected.\n");
			break;
		}

		char getURI[] = "GET / HTTP/1.1\r\n"
			"Accept: text/html, application/xhtml+xml, image/jxr\r\n"
			"Accept-Encoding: gzip, deflate\r\n"
			"Accept-Language: en-US, en; q=0.8, zh-Hans-CN; q=0.5, zh-Hans; q=0.3\n"
			"DNT: 1\r\n"
			"Host: news.qq.com\r\n"
			"User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)\r\n"
			"\r\n";
		r = send(h, getURI, (int)strlen(getURI), 0);
		if (r == SOCKET_ERROR)
			break;

		r = recv(h, largeBuf, sizeof(largeBuf), 0);
		shutdown(h, SD_BOTH);
		if (r > 0)
			printf_s("\r\n\n%d octets received:\r\n\n%s", r, largeBuf);
		else if (r == SOCKET_ERROR)
			break;
		round++;
	}
	//
	return 0;
}



#pragma pack(push)
#pragma pack(1)
typedef void *PVOID;

static int unit_test_atomic()
{
	union _s_atomic_body
	{
		struct
		{
			union
			{
				int32_t _dw1;
				struct
				{
					octet b1;
					octet b2;
					octet b3;
					octet b4;
				};
			};
			union
			{
				int32_t  _dw2;
				struct
				{
					octet b5;
					octet b6;
					octet b7;
					octet b8;
				};
			};
		};
		void *p;
		uint64_t _qw;
	} storage;
#define DUMP_STORAGE()										\
	printf("Stored: %02X%02X %02X%02X %02X%02X %02X%02X\n", \
	storage.b1, storage.b2, storage.b3, storage.b4, 		\
	storage.b5, storage.b6, storage.b7, storage.b8)

	printf("Size of the storage: %d\n", (int)sizeof(storage));
	*((int64_t *)&storage) = 0;
	DUMP_STORAGE();

	printf("Setting to 1:\n");
	InterlockedExchange64((int64_t *)&storage, 1);
	DUMP_STORAGE();

	printf("Setting first dword to 2:\n");
	_InterlockedExchange((long *)&storage._dw1, 2);
	DUMP_STORAGE();

	printf("Adding first dword by 3:\n");
	_InterlockedExchangeAdd((long *)&storage._dw1, 3);
	DUMP_STORAGE();

	printf("Increment first dword:\n");
	_InterlockedIncrement((long *)&storage._dw1);
	DUMP_STORAGE();

	printf("The first 32-bit word is: 0x%08X\n", (uint32_t)_InterlockedOr((long *)&storage._dw1, 0));

	printf("Setting pointer from %p to NULL:\n", _InterlockedExchangePointer(&storage.p, 0));
	DUMP_STORAGE();

	printf("Force setting the whole qword to 1:\n");
	_InterlockedCompareExchange(&storage._qw, 1, 0);
	DUMP_STORAGE();

	printf("Setting second dword to 1 after comparing at first:\n");
	_InterlockedCompareExchange((long *)&storage._dw2, 1, 0);
	DUMP_STORAGE();

	printf("Resetting the pointer from %p to NULL:\n"
		, _InterlockedExchangePointer(&storage.p, 0));
	DUMP_STORAGE();

	printf("Setting the pointer from %p to some legal internal memory address:\n"
		, _InterlockedCompareExchangePointer(&storage.p, &storage._dw1, 0));
	DUMP_STORAGE();

	octet b = _InterlockedOr8((char *)&storage.b2, 0);
	printf("The second byte is: %X\n", b);

	printf("Setting the second octet to some arbitrary value after comparing at first:\n");
	_InterlockedCompareExchange8((char *)&storage.b2, '\xCC', b);
	DUMP_STORAGE();

	return 0;
}
#pragma pack(pop)
