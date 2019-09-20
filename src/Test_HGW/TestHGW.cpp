// TestHGW.cpp : Defines the entry point for the console application.
// This program is a mixed test of FSP http and socks gateway server


#include "stdafx.h"


int main()
{
	WSADATA wsaData;
	int r;
	SOCKET h;

	if(! unit_test())
		return -1;

	if ((r = WSAStartup(0x202, &wsaData)) < 0)
	{
		printf_s("Cannot start up Windows socket service provider.\n");
		return -1;
	}

	h = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (h == SOCKET_ERROR)
	{
		printf_s("socket() failed with error: %d\n", WSAGetLastError());
		return -1;
	}

	sockaddr_in remoteEnd;
	remoteEnd.sin_addr.S_un.S_addr = IN4ADDR_LOOPBACK;
	remoteEnd.sin_family = AF_INET;
	remoteEnd.sin_port = htons(1080);
	memset(remoteEnd.sin_zero, 0, sizeof(remoteEnd.sin_zero));

	r = connect(h, (sockaddr *)&remoteEnd, sizeof(sockaddr_in));
	if (r == SOCKET_ERROR)
	{
		printf_s("listen() failed with error: %d\n", WSAGetLastError());
		closesocket(h);
		return -1;
	}

	// char request[] = "\x04\x01\0\x50\x7F\000\000\001Sciter"; // 127.0.0.1:80
	// char request[] = "\x04\x01\0\x50\xC0\xA8\x09\x71Sciter";	// 192.168.9.113:80
	char request[]  =	"\x04\x01\0\x50\x7D\x27\x34\x1ASciter";	// http://news.qq.com:80 125.39.52.26:80
	r = send(h, request, sizeof(request), 0);
	if(r == SOCKET_ERROR)
	{
		printf_s("send socks request failed with error number: %d\n", WSAGetLastError());
		goto l_bailout;
	}
	printf_s("%d bytes sent for SOCKS CONNECT\n", r);

	char buf[8];	// what expected is 8 bytes SOCKS v4 response
	r = recv(h, buf, sizeof(buf), 0);
	if(r == SOCKET_ERROR)
	{
		printf_s("recv socks response failed with error number: %d\n", WSAGetLastError());
		goto l_bailout;
	}
	if(buf[1] != 90)
	{
		printf_s("Connect request rejected.\n");
		r = -1;
		goto l_bailout;
	}

	// char *getURI = "OPTIONS * HTTP/1.1\r\n" // Not supported by the remote end?
	char *getURI = "GET / HTTP/1.1\r\n"
		"Accept: text/html, application/xhtml+xml, image/jxr\r\n"
		"Accept-Encoding: gzip, deflate\r\n"
		"Accept-Language: en-US, en; q=0.8, zh-Hans-CN; q=0.5, zh-Hans; q=0.3\n"
		"Connection: Keep-Alive\r\n"
		"DNT: 1\r\n"
		"Host: news.qq.com\r\n"
		"User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)\r\n"
		"\r\n";
	//	"Host: news.qq.com\r\n"
	//	"\r\n";
	//char *getURI = "GET /cdn_djl.js HTTP/1.1\r\n"
	//	"Host: jsqmt.qq.com\r\n"
	//	"Accept: application/javascript,*/*;q=0.8\r\n"
	//	"Referer:http://news.qq.com\r\n"
	//	"\r\n";
	// Cookie, User-Agent, Accept-Language were not sent
	r = send(h, getURI, strlen(getURI), 0);
	if(r == SOCKET_ERROR)
	{
		printf_s("send request failed with error number: %d\n", WSAGetLastError());
		goto l_bailout;
	}
	printf_s("%d bytes sent for HTTP request\n", r);
	
	static char largeBuf[0x100000];	// 1MB
	do
	{
		r = recv(h, largeBuf, sizeof(largeBuf), 0);
		if(r > 0)
			printf_s("\r\n\n%d\r\n\n%s", r, largeBuf);
	} while(r > 0);

	if(r == SOCKET_ERROR)
		printf_s("recv response body failed with error number: %d\n", WSAGetLastError());

l_bailout:
	shutdown(h, SD_BOTH);
	closesocket(h);
	return r;
}
