// A client support the Challenge-responde Handshake Authenticated Key Agreement protocol [/Signature: certificate is out-of-band]
// UNERSOLVED! Put client's identity for hashing?
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <io.h>
#include <errno.h>
#include <fcntl.h>
#include <share.h>

#include "../FSP_API.h"
#include "../FileSyncServer/CHAKA.h"

// Forward declaration of an auxilary function
int ReportLastError();

// Branch controllers
extern int	FSPAPI onMultiplying(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);

const char *	theUserId = "FSP_Sciter";
static HANDLE	hFile;
static char		fileName[MAX_PATH];

/**
 * The key agreement block
 */
// TODO: should associated it with the session!
ALIGN(8)
static SCHAKAPublicInfo chakaPubInfo;

static unsigned char bufPrivateKey[CRYPTO_NACL_KEYBYTES];
static unsigned char bufSharedKey[CRYPTO_NACL_KEYBYTES];
ALIGN(8)
static uint8_t	clientInputHash[CRYPT_NACL_HASHBYTES];

// Forward declarations
static int	FSPAPI onConnected(FSPHANDLE, PFSP_Context);
static void FSPAPI onPublicKeySent(FSPHANDLE, FSP_ServiceCode, int);
static void FSPAPI onServerResponseReceived(FSPHANDLE, FSP_ServiceCode, int);
static int	FSPAPI onClientResponseSent(FSPHANDLE, void *, int32_t, BOOL);
static void FSPAPI onReceiveFileNameReturn(FSPHANDLE, FSP_ServiceCode, int);
static int	FSPAPI onReceiveNextBlock(FSPHANDLE, void *, int32_t, BOOL);



// dispose/recycle resource
static void finalize()
{
	if(hFile != NULL && hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
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



// the server would send the filename in the first message. the client should change the name
// in case it is in the same directory of the same machine 
int Download(char *remoteAppURL)
{
	int result = 0;

	FSP_SocketParameter parms;
	memset(& parms, 0, sizeof(parms));
	parms.onAccepting = onMultiplying;
	parms.onAccepted = onConnected;
	parms.onError = onError;
	parms.recvSize = MAX_FSP_SHM_SIZE;	// 4MB
	parms.sendSize = 0;	// the underlying service would give the minimum, however
	if(Connect2(remoteAppURL, & parms) == NULL)
	{
		printf("Failed to initialize the connection in the very beginning\n");
		return -1;
	}

	return 0;
}




// On connected, send the public key and the client nonce to the remote end.
// *S --> C, [in FSP's ACK_CONNECT_REQUEST]: /Welcome and identity of S/Public Key_S
// *C --> S, [in FSP's PERSIST, had better with EoT]: /Public Key_C/Timestamp_C/Greeting and identity of C
//	S --> C, [PERSIST]: the salt, Timestamp_S, Random_S, S's response to the C's challenge
//		Suppose salted_password = HASH(salt | registered password)
//		Response: HASH(salted_password | HASH((C's public key, C's timestamp) XOR S's random(repeated))))
//	[C get the shared secret]
//	C --> S, [PERSIST]: C's reponse to the S's challenge
//		Let salted_input_password = HASH(salt | inputted password)
//		Reponse: HASH(salted_input_password | HASH((S's public key, S's timestamp) XOR S's random(repeated)))
//	[S get the shared secret]
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
	printf_s("%s\n", ctx->welcome);

	memset(chakaPubInfo.serverPublicKey, 0, CRYPTO_NACL_KEYBYTES);
	memcpy(chakaPubInfo.serverPublicKey, (const char *)ctx->welcome + mLen, CRYPTO_NACL_KEYBYTES);

	CryptoNaClKeyPair(chakaPubInfo.clientPublicKey, bufPrivateKey);
	chakaPubInfo.clientNonce = htobe64(NowUTC()); 

	WriteTo(h, chakaPubInfo.clientPublicKey, sizeof(chakaPubInfo.clientPublicKey) + sizeof(chakaPubInfo.clientNonce), 0, onPublicKeySent);
	return 0;
}




// On acknowledgement that the public key has been sent read the name of the file
// that the remote end is to send and is to be saved by the near end
static void FSPAPI onPublicKeySent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	printf_s("Result of sending public key: %d\n", r);
	if(r < 0)
	{
		Dispose(h);
		return;
	}

	// And suffixed with the client's identity
	WriteTo(h, (void *)theUserId, strlen(theUserId) + 1, EOF, NULL);

	ReadFrom(h, chakaPubInfo.salt, sizeof(chakaPubInfo.salt), onServerResponseReceived);
}



//	S --> C, [in FSP's ACK_CONNECT_REQUEST]: /Welcome and identity of S/Public Key_S
//  C --> S, [in FSP's PERSIST, had better with EoT]: /Greeting and identity of C/Public Key_C/Timestamp_C
// *S --> C, [PERSIST]: the salt, Timestamp_S, Random_S, S's response to the C's challenge
//		Suppose salted_password = HASH(salt | registered password)
//		Response: HASH(salted_password | HASH((C's public key, C's timestamp) XOR S's random(repeated))))
// *[C get the shared secret]
// *C --> S, [PERSIST]: C's reponse to the S's challenge
//		Let salted_input_password = HASH(salt | inputted password)
//		Reponse: HASH(salted_input_password | HASH((S's public key, S's timestamp) XOR S's random(repeated)))
//	[S get the shared secret]
static void FSPAPI onServerResponseReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	ReadFrom(h, & chakaPubInfo.serverNonce, sizeof(chakaPubInfo.serverNonce) + sizeof(chakaPubInfo.serverRandom), NULL);
	ReadFrom(h, chakaPubInfo.peerResponse, sizeof(chakaPubInfo.peerResponse), NULL);

	// The client prechecks the validity of nonce. If clock 'difference is too high'(?), reject the request
	int64_t d = be64toh(chakaPubInfo.serverNonce) - be64toh(chakaPubInfo.clientNonce);
	if(d < -60000000 || d > 60000000)
	{
		printf_s("Protocol is broken: timer difference exceeds 1 minute.\n");
		Dispose(h);
		return;
	}

	// The peer should have commit the transmit transaction. Integrity is assured
	FSPControl(h, FSP_GET_PEER_COMMITTED, (ulong_ptr) & r);
	if(r == 0)
	{
		printf_s("Protocol is broken: length of client's id should not exceed MAX_PATH\n");
		Dispose(h);
		return;
	}

	// second round C->S
	char inputPassword[80];
	fputs("Please input the password: ", stdout);
	gets_s<80>(inputPassword);	// this is just a demonstration, so don't hide the input

	// Suppose the client get the salt
	uint8_t *clientPasswordHashMaterial = (uint8_t *)_alloca(sizeof(chakaPubInfo.salt) + strlen(inputPassword));
	memcpy(clientPasswordHashMaterial, chakaPubInfo.salt, sizeof(chakaPubInfo.salt));
	memcpy(clientPasswordHashMaterial + sizeof(chakaPubInfo.salt), inputPassword, strlen(inputPassword));
	CryptoNaClHash(clientInputHash, clientPasswordHashMaterial, sizeof(chakaPubInfo.salt) + strlen(inputPassword));

	// validate the server's response
	// second round S->C
	ALIGN(8)
	uint8_t serverResponseMaterial[CRYPTO_NACL_KEYBYTES + sizeof(chakaPubInfo.clientNonce)];
	uint8_t expectedPresponse[CRYPT_NACL_HASHBYTES * 2];
	uint8_t expectedResponse[CRYPT_NACL_HASHBYTES];
	memcpy(serverResponseMaterial, chakaPubInfo.clientPublicKey, CRYPTO_NACL_KEYBYTES);
	*(uint64_t *)(serverResponseMaterial + CRYPTO_NACL_KEYBYTES) = chakaPubInfo.clientNonce;
	// we're definitely sure that the length of serverResponseMaterial is some multiplication of 8-octect
	for (register int i = 0; i < sizeof(serverResponseMaterial) / sizeof(chakaPubInfo.serverRandom); i++)
	{
		((uint64_t *)serverResponseMaterial)[i] ^= chakaPubInfo.serverRandom;
	}

	CryptoNaClHash(expectedPresponse + CRYPT_NACL_HASHBYTES, serverResponseMaterial, sizeof(serverResponseMaterial));
	memcpy(expectedPresponse, clientInputHash, CRYPT_NACL_HASHBYTES);
	CryptoNaClHash(expectedResponse, expectedPresponse, sizeof(expectedPresponse));

	// The client check the response of the server
	r = memcmp(expectedResponse, chakaPubInfo.peerResponse, CRYPT_NACL_HASHBYTES);
	if(r != 0)
	{
		Dispose(h);
		return;
	}

	ALIGN(8)
	uint8_t clientResponseMaterial[CRYPTO_NACL_KEYBYTES + sizeof(chakaPubInfo.serverNonce)];
	uint8_t clientPresponse[CRYPT_NACL_HASHBYTES * 2];
	uint8_t clientResponse[CRYPT_NACL_HASHBYTES];
	memcpy(clientResponseMaterial, chakaPubInfo.serverPublicKey, CRYPTO_NACL_KEYBYTES);
	*(uint64_t *)(clientResponseMaterial + CRYPTO_NACL_KEYBYTES) = chakaPubInfo.serverNonce;
	// we're definitely sure that the length of clientResponseMaterial is some multiplication of 8-octect
	for (register int i = 0; i < sizeof(clientResponseMaterial) / sizeof(chakaPubInfo.serverRandom); i++)
	{
		((uint64_t *)clientResponseMaterial)[i] ^= *((uint64_t *)chakaPubInfo.serverRandom);
	}
	CryptoNaClHash(clientPresponse + CRYPT_NACL_HASHBYTES, clientResponseMaterial, sizeof(clientResponseMaterial));
	memcpy(clientPresponse, clientInputHash, CRYPT_NACL_HASHBYTES);
	CryptoNaClHash(clientResponse, clientPresponse, sizeof(clientPresponse));

	// Async task?
	WriteTo(h, clientResponse, sizeof(clientResponse), EOF, NULL);

	//
	CryptoNaClGetSharedSecret(bufSharedKey, chakaPubInfo.serverPublicKey, bufPrivateKey);

	printf_s("\tTo install the shared key instantly...\n");
	InstallAuthenticKey(h, bufSharedKey, CRYPTO_NACL_KEYBYTES, INT32_MAX);

	printf_s("\nTo read filename...\t");
	if(ReadFrom(h, fileName, sizeof(fileName), onReceiveFileNameReturn) < 0)
	{
		Dispose(h);
		return;
	}
}




static void FSPAPI onReceiveFileNameReturn(FSPHANDLE h, FSP_ServiceCode resultCode, int resultValue)
{
	if(resultCode != FSP_NotifyDataReady)
	{
		printf("\nUnknown result code %d returned by FSP LLS, returned = %\n", resultCode, resultValue);
		Dispose(h);
		return;
	}

	// try to create a new file of the same name. if failed on error file already exists, 
	// try to change the filename by append a 'C'[if it does not have suffix].
	// if the new filename exceed MAX_PATH, confuscate the last character
	printf_s("done.\nRemote filename: %s\n", fileName);
	try
	{
 		// TODO: exploit to GetDiskFreeSpace to take use of SECTOR size
		// _aligned_malloc
		// the client should take use of 'FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH' for ultimate integrity
		hFile = CreateFileA(fileName
			, GENERIC_WRITE
			, 0	// shared none
			, NULL
			, CREATE_NEW
			, FILE_FLAG_POSIX_SEMANTICS | FILE_FLAG_WRITE_THROUGH
			, NULL);
		// | FILE_FLAG_NO_BUFFERING [require data block alignment which condition is too strict]
		if(hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS)
		{
			char linebuf[80];
			printf_s("Overwrite existent file? Y/n: ");
			gets_s(linebuf, sizeof(linebuf));
			int c = toupper(linebuf[0]);
			if(c != 'Y')
			{
				Dispose(h);
				return;
			}
			//
			hFile = CreateFileA(fileName
				, GENERIC_WRITE
				, 0	// shared none
				, NULL
				, CREATE_ALWAYS
				, FILE_FLAG_POSIX_SEMANTICS | FILE_FLAG_WRITE_THROUGH
				, NULL);
			// | FILE_FLAG_NO_BUFFERING [require data block alignment which condition is too strict]
			if(hFile == INVALID_HANDLE_VALUE)
			{
				ReportLastError();	// "Cannot create the new file"
				Dispose(h);
				return;
			}
		}
		//
		printf_s("To read content with inline buffering...\n");
		RecvInline(h, onReceiveNextBlock);
	}
	catch(...)
	{
		Dispose(h);
	}
}






//
// Continue to download the Simple Artcrafted Web Site description file. Application layer acknowledgement is UNNECESSARY
//
static int FSPAPI onReceiveNextBlock(FSPHANDLE h, void *buf, int32_t len, BOOL eot)
{
	if(buf == NULL)
	{
		printf("FSP Internal panic? Receive nothing when calling the CallbackPeeked?\n");
		Dispose(h);
		return -1;
	}

	printf_s("%d bytes read, to write the buffer directly...\n", len);

	DWORD bytesWritten;
	if(! WriteFile(hFile, buf, len, & bytesWritten, NULL))
	{
		ReportLastError();
		Dispose(h);
		return -1;
	}

	printf_s("%d bytes written to local storage.\n", bytesWritten);
	// needn't UnlockPeeked as Shutdown would forcefully close the receive window
	// and return a non-zero would let the occupied receive buffer free
	if(eot)
	{
		printf_s("All data have been received, to acknowledge...\n");
		// Respond with a code saying no error
		//return WriteTo(h, "0000", 4, EOF, onAcknowledgeSent);
		return 0;
	}

	return 1;
}


//if(Shutdown(h, onFinished) < 0)
	//{
	//	printf_s("Cannot shutdown gracefully in the final stage.\n");
	//	Dispose(h);
	//}



// The entry function of the group. Most statements in this function is for tracing purpose.
int	FSPAPI onMultiplying(FSPHANDLE hRev, PFSP_SINKINF p, PFSP_IN6_ADDR remoteAddr)
{
	//
	printf_s("\nTo accept multiplied handle of FSP session: %p\n", hRev);
	printf_s("Interface#%d, fiber#%u\n", p->ipi6_ifindex, p->idALF);
	// no be32toh() for local; note that for IPv6 network, little-endian CPU, the peer's remoteAddr->idALF wouldn't match it
	printf_s("Remote address: 0x%llX::%X::%X\n", be64toh(remoteAddr->u.subnet), be32toh(remoteAddr->idHost), be32toh(remoteAddr->idALF));

	// TODO:
	return 0;	// no opposition
}



// A auxilary function
int ReportLastError()
{
	int	err = GetLastError();
	LPVOID lpMsgBuf;

	printf_s("Error code = %d\n", err);
	if (FormatMessageA( 
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPSTR) &lpMsgBuf,
		0,
		NULL )) 
	{
		printf_s("\tError: %s\n", lpMsgBuf);
		LocalFree( lpMsgBuf );
	}

	return err;
}
