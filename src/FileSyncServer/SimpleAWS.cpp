/*
 * Demonstration of the Challenge-response Handshake Authenticated Key Agreement protocol, the server side
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
// *S --> C, [in FSP's ACK_CONNECT_REQUEST]: /Welcome and identity of S/Public Key_S
// *C --> S, [in FSP's PERSIST, had better with EoT]: /Public Key_C/Timestamp_C/Greeting and identity of C
//	S --> C, [PERSIST]: the salt, Timestamp_S, Random_S, S's response to the C's challenge
//		Suppose salted_password = HASH(salt | registered password)
//		Response: HASH(salted_password | HASH((C's public key, C's timestamp) XOR S's random(repeated))))
//	[C get the shared secret][hmac_sm3(salted_password, Curve25519-shared secret)]
//	C --> S, [PERSIST]: C's reponse to the S's challenge
//		Let salted_input_password = HASH(salt | inputted password)
//		Reponse: HASH(salted_input_password | HASH((S's public key, S's timestamp) XOR S's random(repeated)))
//	[S get the shared secret][hmac_sm3(salted_password, Curve25519-shared secret)]
#include "stdafx.h"
#include "defs.h"

# define REPORT_ERROR_ON_TRACE() \
	TraceLastError(__FILE__, __LINE__, __FUNCDNAME__, "ERROR REPORT")
# define REPORT_ERRMSG_ON_TRACE(s1) \
	TraceLastError(__FILE__, __LINE__, __FUNCDNAME__, (s1))
void TraceLastError(char * fileName, int lineNo, const char *funcName, const char *s1);

// The path to be searched. It could be patterned.
static TCHAR pattern[MAX_PATH];

/**
 * The key agreement block
 */
// TODO: should associated salt, password and passwordHash with the session!
const octet salt[CRYPTO_SALT_LENGTH] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
const char *password = "Passw0rd";
ALIGN(8)
static uint8_t passwordHash[CRYPTO_NACL_HASHBYTES];

static SCHAKAPublicInfo chakaPubInfo;
static char sessionClientIdString[_MAX_PATH];

static void FSPAPI onServerResponseSent(FSPHANDLE h, FSP_ServiceCode c, int r);
static void FSPAPI onClientResponseReceived(FSPHANDLE h, FSP_ServiceCode c, int r);
static void FSPAPI onFileListSent(FSPHANDLE h, FSP_ServiceCode c, int r);


//
// by default return the file 'index.saws' under the given path
//
void PrepareServiceSAWS(LPCTSTR pathName)
{
	HANDLE h = CreateFile(pathName
		, GENERIC_READ
		, FILE_SHARE_READ
		, NULL
		, OPEN_EXISTING
		, FILE_FLAG_BACKUP_SEMANTICS  + FILE_FLAG_SEQUENTIAL_SCAN
		, NULL);
	if(h == INVALID_HANDLE_VALUE)
	{
		REPORT_ERRMSG_ON_TRACE("path not accessible");
		return;
	}
	CloseHandle(h);

	_tcscpy_s(pattern, pathName);
	_tcscat_s(pattern, _T("\\*"));
	//
	MakeSaltedPassword(passwordHash, salt, password);
}



// On connected, send the public key and the client nonce to the remote end.
int FSPAPI ServiceSAWS_onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nSimple AWS onAccepted: handle of FSP session %p\n", h);

	// TODO: check connection context
	extern unsigned char * bufPublicKey;
	InitCHAKAServer(chakaPubInfo, bufPublicKey);

	ReadFrom(h, & chakaPubInfo.peerPublicKey, sizeof(chakaPubInfo.peerPublicKey), onPublicKeyReceived);
	return 0;
}



// Get the client's ID and nonce, fetch the salted password
static void FSPAPI onPublicKeyReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	ReadFrom(h, & chakaPubInfo.clientNonce, sizeof(chakaPubInfo.clientNonce), NULL);

	octet buf[sizeof(sessionClientIdString)];
	int nBytes = ReadFrom(h, buf, sizeof(buf), NULL);
	// assert(nBytes <= sizeof(sessionClientIdString));
	ChakaStreamcrypt((octet *)sessionClientIdString
		, chakaPubInfo.clientNonce
		, buf, nBytes
		, chakaPubInfo.peerPublicKey, bufPrivateKey);

	FSPControl(h, FSP_GET_PEER_COMMITTED, (ULONG_PTR) & r);
	if(r == 0)
	{
		printf_s("Protocol is broken: length of client's id should not exceed MAX_PATH\n");
		Dispose(h);
		return;
	}

	//TODO: map the client's id to its salt and password hash value

	octet serverResponse[CRYPTO_NACL_HASHBYTES];
	if(! CHAKAChallengeByServer(chakaPubInfo, serverResponse, passwordHash))
	{
		Dispose(h);
		return;
	}
	memcpy(chakaPubInfo.salt, salt, sizeof(salt));	// should read from database

	WriteTo(h, chakaPubInfo.salt, sizeof(chakaPubInfo.salt) + sizeof(chakaPubInfo.serverNonce) + sizeof(chakaPubInfo.serverRandom), 0, NULL);
	WriteTo(h, serverResponse, sizeof(serverResponse), EOF, onServerResponseSent);
}



static void FSPAPI onServerResponseSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	ReadFrom(h, chakaPubInfo.peerResponse, sizeof(chakaPubInfo.peerResponse), onClientResponseReceived);
}



static void FSPAPI onClientResponseReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(! CHAKAValidateByServer(chakaPubInfo, passwordHash))
	{
		Dispose(h);
		return;
	}
	//
	printf_s("\tTo install the session key instantly...\n");
	octet bufSharedKey[SESSION_KEY_SIZE];
	ChakaDeriveKey(bufSharedKey, passwordHash, chakaPubInfo, bufPrivateKey);
	InstallSessionKey(h, bufSharedKey, SESSION_KEY_SIZE, INT32_MAX);

	// To list files remotely
	WIN32_FIND_DATA findFileData;
	HANDLE hFind = FindFirstFile(pattern, & findFileData); 
	if(hFind == INVALID_HANDLE_VALUE)
	{
		_tprintf_s(_T("Directory is empty: %s\n"), pattern);
		return;
	}
	//
	octet buffer[MAX_PATH * 2 + 2];
	do
	{
		TCHAR *fName = findFileData.cFileName;
		_tprintf_s(_T("File or directory: %s\n"), fName);
		if(_tcscmp(fName, _T(".")) == 0 || _tcscmp(fName, _T("..")) == 0)
			continue;
#ifdef _MBCS
		int nBytes = LocalMBCSToUTF8(buffer, sizeof(buffer), fName);
#else
		int nBytes = WideStringToUTF8(buffer, sizeof(buffer), fName);
#endif
		WriteTo(h, buffer, nBytes, 0, NULL);
	} while (FindNextFile(hFind, &findFileData));
	//
	FindClose(hFind);

	Commit(h, onFileListSent);
}



//
static void FSPAPI onFileListSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		Dispose(h);
		return;
	}

	ReadFrom(h, linebuf, sizeof(linebuf), onResponseReceived);
}



// Defined here only because this source file is shared across modules
# define ERROR_SIZE	1024	// FormatMessage buffer size, no dynamic increase
void TraceLastError(char * fileName, int lineNo, const char *funcName, const char *s1)
{
	DWORD err = GetLastError();
	CHAR buffer[ERROR_SIZE];
	printf("\n/**\n * %s, line %d\n * %s\n * %s\n */\n", fileName, lineNo, funcName, s1);

	buffer[0] = 0;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM
		, NULL
		, err
		, LANG_USER_DEFAULT
		, (LPTSTR) & buffer
		, ERROR_SIZE
		, NULL);
	if(buffer[0] != 0)
		puts(buffer);
}
