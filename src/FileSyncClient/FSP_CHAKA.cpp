/*
 * A client support the Challenge-response Handshake Authenticated Key Agreement protocol
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
// UNERSOLVED! Put client's identity for hashing? [/Signature: certificate is out-of-band]
// Not bothered to apply RFC8018 PKCS #5: Password-Based Cryptography Specification
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <io.h>
#include <errno.h>
#include <fcntl.h>
#include <share.h>

#include "../FSP_API.h"
#include "../Crypto/CHAKA.h"

// Forward declaration of an auxilary function
int ReportLastError();

const char *	theUserId = "FSP_Sciter";

/**
 * The key agreement block
 */
// TODO: should associated it with the session!
ALIGN(8)
static SCHAKAPublicInfo chakaPubInfo;
static unsigned char bufPrivateKey[CRYPTO_NACL_KEYBYTES];

// Forward declarations
static int	FSPAPI onConnected(FSPHANDLE, PFSP_Context);
static void FSPAPI onServerResponseReceived(FSPHANDLE, FSP_ServiceCode, int);
static int	FSPAPI onClientResponseSent(FSPHANDLE, void *, int32_t, BOOL);
//
static bool	FSPAPI onReceiveNextBlock(FSPHANDLE, void *, int32_t, bool);
static void FSPAPI onAcknowledgeSent(FSPHANDLE, FSP_ServiceCode, int);

// an internal function to parsing each memory segment received 'inline'
static int ParseBlock(octet *, int32_t);

static bool finished;

// dispose/recycle resource
static void finalize()
{
	finished = true;
	// TODO: further per-process clean-up works here!
}


// The call back function on exception notified. Just report error and simply abort the program.
static void FSPAPI onError(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Notify: socket %p, service code = %d, return %d\n", h, code, value);
	finalize();
	return;
}



// Forward definition of the callback function that handles the event of Connection Released (Shutdown)
static void FSPAPI onFinished(FSPHANDLE h, FSP_ServiceCode code, int value)
{
	printf_s("Socket %p, session was to shut down.\n", h);
	if(code != FSP_NotifyRecycled)
		printf_s("Should got ON_RECYCLED, but service code = %d, return %d\n", code, value);

	finalize();
	return;
}



int ToAcceptPushedDirectory(char *remoteAppURL)
{
	int result = 0;

	FSP_SocketParameter parms;
	memset(& parms, 0, sizeof(parms));
	parms.onAccepting = NULL;
	parms.onAccepted = onConnected;
	parms.onError = onError;
	parms.recvSize = MAX_FSP_SHM_SIZE;	// 4MB
	parms.sendSize = 0;	// the underlying service would give the minimum, however
	if(Connect2(remoteAppURL, & parms) == NULL)
	{
		printf("Failed to initialize the connection in the very beginning\n");
		return -1;
	}

	while(!finished)
		Sleep(50);	// yield CPU out for about 1/20 second

	return 0;
}




// On connected, send the public key and the client nonce to the remote end.
static int	FSPAPI  onConnected(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nHandle of FSP session: %p", h);
	if(h == NULL)
	{
		printf_s("\n\tConnection failed.\n");
		finalize();
		return -1;
	}

	int mLen = strlen((const char *)ctx->welcome) + 1;
	printf_s("\tWelcome message length: %d\n", ctx->len);
	printf_s("%s\n", (char *)ctx->welcome);

	InitCHAKAClient(chakaPubInfo, bufPrivateKey);
	memcpy(chakaPubInfo.peerPublicKey, (const char *)ctx->welcome + mLen, CRYPTO_NACL_KEYBYTES);

	WriteTo(h, chakaPubInfo.selfPublicKey, sizeof(chakaPubInfo.selfPublicKey), 0, NULL);
	WriteTo(h, & chakaPubInfo.clientNonce, sizeof(chakaPubInfo.clientNonce), 0, NULL);
	// And suffixed with the client's identity

	int nBytes = strlen(theUserId) + 1;
	octet buf[MAX_PATH];
	// assert(strlen(theUserId) + 1 <= sizeof(buf));
	ChakaStreamcrypt(buf
		, chakaPubInfo.clientNonce
		, (octet *)theUserId, nBytes
		, chakaPubInfo.peerPublicKey, bufPrivateKey);
	WriteTo(h, buf, nBytes, TO_END_TRANSACTION, NULL);

	ReadFrom(h, chakaPubInfo.salt, sizeof(chakaPubInfo.salt), onServerResponseReceived);
	return 0;
}



// second round C->S
static void FSPAPI onServerResponseReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	ReadFrom(h, & chakaPubInfo.serverNonce, sizeof(chakaPubInfo.serverNonce) + sizeof(chakaPubInfo.serverRandom), NULL);
	ReadFrom(h, chakaPubInfo.peerResponse, sizeof(chakaPubInfo.peerResponse), NULL);
	// The peer should have commit the transmit transaction. Integrity is assured
	FSPControl(h, FSP_GET_PEER_COMMITTED, (ulong_ptr) & r);
	if(r == 0)
	{
		printf_s("Protocol is broken: length of client's id should not exceed MAX_PATH\n");
		Dispose(h);
		return;
	}

	octet clientInputHash[CRYPTO_NACL_HASHBYTES];
	char inputPassword[80];
	fputs("Please input the password: ", stdout);
	gets_s<80>(inputPassword);	// this is just a demonstration, so don't hide the input
	MakeSaltedPassword(clientInputHash, chakaPubInfo.salt, inputPassword);

	octet clientResponse[CRYPTO_NACL_HASHBYTES];
	if(! CHAKAResponseByClient(chakaPubInfo, clientInputHash, clientResponse))
	{
		Dispose(h);
		return;
	}

	WriteTo(h, clientResponse, sizeof(clientResponse), TO_END_TRANSACTION, NULL);

	printf_s("\tTo install the session key instantly...\n");
	octet bufSessionKey[SESSION_KEY_SIZE];
	CryptoNaClGetSharedSecret(bufSessionKey, chakaPubInfo.peerPublicKey, bufPrivateKey);
	InstallMasterKey(h, bufSessionKey, SESSION_KEY_SIZE);

	// The server side write with the stream mode, while the client side read with block buffer mode
	printf_s("\nTo read file list...\n");
	RecvInline(h, onReceiveNextBlock);
}



static char strStrings[1200];	// arbitrary size for test only
static void FSPAPI onStringsRead(FSPHANDLE h, FSP_ServiceCode code, int len)
{
	if(len < 0)
	{
		printf_s("onStringsRead get call back parameter value %d\n", len);
		Dispose(h);
		return;
	}

	ParseBlock((octet *)strStrings, len);
	
	int r;
	FSPControl(h, FSP_GET_PEER_COMMITTED, (ulong_ptr) & r);
	if(! r)
	{
		ReadFrom(h, strStrings, (int)sizeof(strStrings), onStringsRead);
		return;
	}
	//
	printf_s("All data have been received, to acknowledge...\n");
	WriteTo(h, "0000", 4, TO_END_TRANSACTION, onAcknowledgeSent);
}


static void SynchronousRead(FSPHANDLE h)
{
	int len;
	do
	{
		len = ReadFrom(h, strStrings, (int)sizeof(strStrings), NULL);
		if(len > 0)
			ParseBlock((octet *)strStrings, len);	
	} while (len > 0);
	//
	//FSPControl(h, FSP_GET_PEER_COMMITTED, (ulong_ptr) & len);
	//assert(len != 0);
	printf_s("All data have been received, to acknowledge...\n");
	WriteTo(h, "0000", 4, TO_END_TRANSACTION, onAcknowledgeSent);
}


// The iteration body that accept continuous segments of the directory list
// The 'eot' (End of Transaction) flag is to indicate the end of the list
// A reverse application layer acknowledgement message is written back to the remote end
static bool FSPAPI onReceiveNextBlock(FSPHANDLE h, void *buf, int32_t len, bool eot)
{
	if(len == -EPIPE)
	{
//		ReadFrom(h, strStrings, (int)sizeof(strStrings), onStringsRead);
		SynchronousRead(h);
		return false;
	}

	if(buf == NULL)	
	{
		printf_s("FSP Internal panic? Receive nothing when calling the CallbackPeeked?\n");
		Dispose(h);
		return false;
	}

	ParseBlock((octet *)buf, len);

	if(eot)
	{
		printf_s("All data have been received, to acknowledge...\n");
		WriteTo(h, "0000", 4, TO_END_TRANSACTION, onAcknowledgeSent);
		return false;
	}

	return true;
}



static int ParseBlock(octet *utf8str, int32_t len)
{
	static char partialFileName[sizeof(TCHAR) * MAX_PATH + 4];	// buffered partial file name
	static int lenPartial = 0;					// length of the partial name
	TCHAR finalFileName[MAX_PATH];
	int lenCurrent = 0;
	int nScanned = 0;

	// Set the sentinel
	char c = utf8str[len - 1];
	utf8str[len - 1] = 0;

	// continue with previous cross-border string
	if (lenPartial > 0)
	{
		while (utf8str[lenCurrent] != 0)
		{
			lenCurrent++;
			nScanned++;
		}
		// There should be a NUL as the string terminator!
		if (c != 0 && lenCurrent >= len)
		{
			printf_s("Attack encountered? File name too long!\n");
			return -1;
		}
		//
		lenCurrent++;	// Make it null-terminated
		nScanned++;
		memcpy(partialFileName + lenPartial, utf8str, lenCurrent);
#ifdef _MBCS
		UTF8ToLocalMBCS(finalFileName, MAX_PATH, partialFileName);
		printf_s("%s\n", finalFileName);
#else
		UTF8ToWideChars(finalFileName, MAX_PATH, partialFileName, lenPartial + lenCurrent);
		wprintf_s(L"%s\n", finalFileName);
#endif
		// TODO: some further treatment on the final filename here.
		utf8str += lenCurrent;
		lenCurrent = 0;
		lenPartial = 0;
	}
	// A sentinel character is set before scan the input
	do
	{
		while (utf8str[lenCurrent] != 0)
		{
			lenCurrent++;
			nScanned++;
		}
		//
		lenCurrent++;
		nScanned++;
		if (nScanned >= len && c != 0)
		{
			utf8str[lenCurrent - 1] = c;	// so that the sentinel character is copied
			memcpy(partialFileName, utf8str, lenCurrent);
			lenPartial = lenCurrent;
			break;
		}
		//
#ifdef _MBCS
		UTF8ToLocalMBCS(finalFileName, MAX_PATH, (char *)utf8str);
		printf_s("%s\n", finalFileName);
#else
		UTF8ToWideChars(finalFileName, MAX_PATH, (char *)utf8str, lenCurrent);
		wprintf_s(L"%s\n", finalFileName);
#endif
		// TODO: some further treatment on the final filename here.
		utf8str += lenCurrent;
		lenCurrent = 0;
	} while (nScanned < len);
	//
	return nScanned;
}



// This time it is really shutdown
static void FSPAPI onAcknowledgeSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	printf_s("Result of sending the acknowledgement: %d\n", r);
	if(r < 0)
	{
		Dispose(h);
		return;
	}

	if(Shutdown(h, onFinished) < 0)
	{
		printf_s("Cannot shutdown gracefully in the final stage.\n");
		Dispose(h);
	}
}
