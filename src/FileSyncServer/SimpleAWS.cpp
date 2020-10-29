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
// *S --> C, [in FSP's ACK_CONNECT_REQ]: /Welcome and identity of S/Public Key_S
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

// assume that address space layout randomization keep the secret hard to find
static octet	bufPrivateKey[CRYPTO_NACL_KEYBYTES];
static octet*	bufPublicKey;
static octet	bufPeerPublicKey[CRYPTO_NACL_KEYBYTES];

ALIGN(8)
static uint8_t passwordHash[CRYPTO_NACL_HASHBYTES];

static octet bufSharedKey[CRYPTO_NACL_KEYBYTES];
static SCHAKAPublicInfo chakaPubInfo;
static char sessionClientIdString[_MAX_PATH];

static void FSPAPI onPublicKeyReceived(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onServerResponseSent(FSPHANDLE h, FSP_ServiceCode c, int r);
static void FSPAPI onClientResponseReceived(FSPHANDLE h, FSP_ServiceCode c, int r);

static void StartToSendDirectory(FSPHANDLE);


/**
 * Start of an incarnated connection
 */
static int FSPAPI onAccepted(FSPHANDLE, PFSP_Context);


/**
 * For sending directory content
 */

static char	linebuf[80];

static void FSPAPI onFileListSent(FSPHANDLE h, FSP_ServiceCode c, int r);
static void FSPAPI onResponseReceived(FSPHANDLE, FSP_ServiceCode, int);


// The callback function to handle general notification of LLS. Parameters are self-describing.
static void FSPAPI onNotice(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify: socket %p, service code = %d, return %d\n", h, code, value);
	Dispose(h);
	if (value < 0)
		r2Finish = finished = true;
}


// The function called back when an FSP connection was released. Parameters are self-describing
static void FSPAPI onFinish(FSPHANDLE h, FSP_ServiceCode code, int)
{
	printf_s("Socket %p, session was to shut down, service code = %d.\n", h, code);
	Dispose(h);
	r2Finish = finished = true;
}


//
// by default return the file 'index.saws' under the given path
//
bool PrepareServiceSAWS(LPCTSTR pathName)
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
		return false;
	}
	CloseHandle(h);

	_tcscpy_s(pattern, pathName);
	_tcscat_s(pattern, _T("\\*"));
	//
	return true;
}



void ActivateListening(const char* thisWelcome, unsigned short mLen)
{
	// For concept demonstration only: prepare the password data entry
	bufPublicKey = (unsigned char*)thisWelcome + mLen - CRYPTO_NACL_KEYBYTES;
	CryptoNaClKeyPair(bufPublicKey, bufPrivateKey);
	MakeSaltedPassword(passwordHash, salt, password);

	FSP_SocketParameter params;
	FSP_IN6_ADDR atAddress;
	memset(&params, 0, sizeof(params));
	params.onAccepting = onAccepting;
	params.onAccepted = onAccepted;
	params.onError = onNotice;
	params.welcome = thisWelcome;
	params.len = mLen;
	params.sendSize = MAX_FSP_SHM_SIZE;
	params.recvSize = 0;	// minimal receiving for download server

#ifdef _DEBUG
	TranslateFSPoverIPv4(&atAddress, 0, htobe32(80));	//INADDR_ANY
#else
	atAddress.subnet = 0xAAAA00E0;	// 0xE0 00 AA AA	// shall be learned
	atAddress.idHost = 0;
	atAddress.idALF = 0x01000000;		// 0x01 [well, it should be the well-known service number...] 
#endif

	hFspListen = ListenAt(&atAddress, &params);
}



// On connected, send the public key and the client nonce to the remote end.
static int FSPAPI onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nSimple AWS onAccepted: handle of FSP session %p\n", h);

	InitCHAKAServer(chakaPubInfo, bufPublicKey);

	ReadFrom(h, & chakaPubInfo.peerPublicKey, sizeof(chakaPubInfo.peerPublicKey), onPublicKeyReceived);
	return 0;
}



// Get the client's ID and nonce, fetch the salted password
static void FSPAPI onPublicKeyReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		printf_s("Previous ReadFrom@ServiceSAWS_onAccepted asynchronously return %d.\n", r);
		Dispose(h);
		return;
	}

	ReadFrom(h, & chakaPubInfo.clientNonce, sizeof(chakaPubInfo.clientNonce), NULL);
	octet buf[sizeof(sessionClientIdString)];
	int nBytes = ReadFrom(h, buf, sizeof(buf), NULL);
	// assert(nBytes <= sizeof(sessionClientIdString));
	CryptoNaClGetSharedSecret(bufSharedKey, chakaPubInfo.peerPublicKey, bufPrivateKey);
	ChakaStreamcrypt((octet *)sessionClientIdString, buf, nBytes, chakaPubInfo.clientNonce, bufSharedKey);

	if (!HasReadEoT(h))
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

	int n = sizeof(chakaPubInfo.salt) + sizeof(chakaPubInfo.serverNonce) + sizeof(chakaPubInfo.serverRandom);
	WriteTo(h, chakaPubInfo.salt, n, 0, NULL);
	WriteTo(h, serverResponse, sizeof(serverResponse), TO_END_TRANSACTION, onServerResponseSent);
}



static void FSPAPI onServerResponseSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	ReadFrom(h, chakaPubInfo.peerResponse, sizeof(chakaPubInfo.peerResponse), onClientResponseReceived);
}



static void FSPAPI onClientResponseReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		printf_s("Previous ReadFrom@onServerResponseSent asynchronously return %d.\n", r);
		Dispose(h);
		return;
	}

	if(! CHAKAValidateByServer(chakaPubInfo, passwordHash))
	{
		Dispose(h);
		return;
	}
	//
	printf_s("\tTo install the session key instantly...\n");
	InstallMasterKey(h, bufSharedKey, CRYPTO_NACL_KEYBYTES);
	memset(bufSharedKey, 0, CRYPTO_NACL_KEYBYTES);
	memset(bufPrivateKey, 0, CRYPTO_NACL_KEYBYTES);

	if (toSendFile)
		StartToSendFile(h);
	else
		StartToSendDirectory(h);
}



// To list files remotely
static void StartToSendDirectory(FSPHANDLE h)
{
	WIN32_FIND_DATA findFileData;
	HANDLE hFind = FindFirstFile(pattern, &findFileData);
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
		// WriteTo(h, buffer, nBytes, TO_COMPRESS_STREAM, NULL);
	} while (FindNextFile(hFind, &findFileData));
	//
	FindClose(hFind);
	//Commit(h, onFileListSent);
	//if the file list happen to be empty, it should be OK
	buffer[0] = 0;
	WriteTo(h, buffer, 1, TO_END_TRANSACTION, onFileListSent);
	// WriteTo(h, buffer, 1, TO_COMPRESS_STREAM + TO_END_TRANSACTION, onFileListSent);
}



static void FSPAPI onFileListSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if(r < 0)
	{
		Dispose(h);
		return;
	}

	ReadFrom(h, linebuf, sizeof(linebuf), onResponseReceived);
}



// The call back function executed when the upper layer application has acknowledged
static void FSPAPI onResponseReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	if (r < 0)
	{
		printf_s("Wait response got error number %d. To abort.\n", r);
		Dispose(h);
		return;
	}

	printf_s("Response received: %s. To shutdown.\n", linebuf);
	if (Shutdown(h, onFinish) < 0)
	{
		printf_s("What? Cannot shutdown gracefully!\n");
		Dispose(h);
		return;
	}
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
