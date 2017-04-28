/*
 * Simple Artcrafted Web Site
 */
#include "stdafx.h"
#include "defs.h"
#include "CHAKA.h"

# define REPORT_ERROR_ON_TRACE() \
	TraceLastError(__FILE__, __LINE__, __FUNCDNAME__, "ERROR REPORT")
# define REPORT_ERRMSG_ON_TRACE(s1) \
	TraceLastError(__FILE__, __LINE__, __FUNCDNAME__, (s1))
void TraceLastError(char * fileName, int lineNo, const char *funcName, const char *s1);


/**
 * The key agreement block
 */
// TODO: should associated it with the session!
const char *salt = "\001\002\003\004\005\006\007\010";
const char *password = "Passw0rd";
ALIGN(8)
static uint8_t passwordHash[CRYPT_NACL_HASHBYTES];

static SCHAKAPublicInfo chakaPubInfo;
static char sessionClientIdString[_MAX_PATH];

static void FSPAPI onServerResponseSent(FSPHANDLE h, FSP_ServiceCode c, int r);

static void FSPAPI onClientResponseReceived(FSPHANDLE h, FSP_ServiceCode c, int r);

//
// by default return the file 'index.saws' under the given path
//
void PrepareServiceSAWS(const TCHAR *pathName)
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
	//
	CloseHandle(h);
	//
	WIN32_FIND_DATA findFileData;
	TCHAR pattern[MAX_PATH];
	strcpy_s(pattern, pathName);
	strcat_s(pattern, "\\*");
	h = FindFirstFile(pattern, & findFileData); 
	if(h == INVALID_HANDLE_VALUE)
	{
		printf_s("Directory is empty: %s\n", pathName);
		return;
	}
	// Should filter out "." and ".."
	do
	{
		printf_s("File or directory: %s\n", findFileData.cFileName);
	} while(FindNextFile(h, & findFileData));
	//
	FindClose(h);

	// prepare password shadow
	uint8_t *shadowMaterial = (uint8_t *)_alloca(strlen(salt) + strlen(password));
	memcpy(shadowMaterial, salt, strlen(salt));
	memcpy(shadowMaterial + strlen(salt), password, strlen(password));
	CryptoNaClHash(passwordHash, shadowMaterial, strlen(salt) + strlen(password));
}



// On connected, send the public key and the client nonce to the remote end.
//Challenge-responde Handshake Authenticated Key Establishment [/Signature: certificate is out-of-band]
// *S --> C, [in FSP's ACK_CONNECT_REQUEST]: /Welcome and identity of S/Public Key_S
//	C --> S, [in FSP's PERSIST, had better with EoT]: /Greeting and identity of C/Public Key_C/Timestamp_C
//	S --> C, [PERSIST]: the salt, Timestamp_S, Random_S, S's response to the C's challenge
//		Suppose salted_password = HASH(salt | registered password)
//		Response: HASH(salted_password | HASH((C's public key, C's timestamp) XOR S's random(repeated))))
//	[C get the shared secret]
//	C --> S, [PERSIST]: C's reponse to the S's challenge
//		Let salted_input_password = HASH(salt | inputted password)
//		Reponse: HASH(salted_input_password | HASH((S's public key, S's timestamp) XOR S's random(repeated)))
//	[S get the shared secret]
int FSPAPI ServiceSAWS_onAccepted(FSPHANDLE h, PFSP_Context ctx)
{
	printf_s("\nEncyrptedMemory onAccepted: handle of FSP session %p\n", h);
	// TODO: check connection context

	ReadFrom(h, & chakaPubInfo.clientPublicKey, sizeof(chakaPubInfo.clientPublicKey), onPublicKeyReceived);
	return 0;
}



//	S --> C, [in FSP's ACK_CONNECT_REQUEST]: /Welcome and identity of S/Public Key_S
// *C --> S, [in FSP's PERSIST, had better with EoT]: /Timestamp_C/Greeting and identity of C/Public Key_C
// *S --> C, [PERSIST]: the salt, Timestamp_S, Random_S, S's response to the C's challenge
//		Suppose salted_password = HASH(salt | registered password)
//		Response: HASH(salted_password | HASH((C's public key, C's timestamp) XOR S's random(repeated))))
//	[C get the shared secret]
//	C --> S, [PERSIST]: C's reponse to the S's challenge
//		Let salted_input_password = HASH(salt | inputted password)
//		Reponse: HASH(salted_input_password | HASH((S's public key, S's timestamp) XOR S's random(repeated)))
//	[S get the shared secret]
//
//
// Get the client's ID and nonce, fetch the salted password
static void FSPAPI onPublicKeyReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	ReadFrom(h, & chakaPubInfo.clientNonce, sizeof(chakaPubInfo.clientNonce), NULL);
	// TODO: read varible-length string
	ReadFrom(h, & sessionClientIdString, sizeof(sessionClientIdString), NULL);

	FSPControl(h, FSP_GET_PEER_COMMITTED, (ULONG_PTR) & r);
	if(r == 0)
	{
		printf_s("Protocol is broken: length of client's id should not exceed MAX_PATH\n");
		Dispose(h);
		return;
	}

	// prepare the random bits (as an alternative to HMAC), should associated with 'h' - per session random
	randombytes(& chakaPubInfo.serverRandom, sizeof(chakaPubInfo.serverRandom));
	chakaPubInfo.serverNonce = htobe64(NowUTC());

	// The server precheck validity of nonce. If clock 'difference is too high'(?), reject the request
	int64_t d = be64toh(chakaPubInfo.serverNonce) - be64toh(chakaPubInfo.clientNonce);
	if(d < -60000000 || d > 60000000)	// i.e. 60 seconds
	{
		printf_s("Protocol is broken: timer difference exceeds 1 minute.\n");
		Dispose(h);
		return;
	}

	// UNERSOLVED! Put client's identity for hashing?
	// second round S->C
	ALIGN(8)
	uint8_t serverResponseMaterial[CRYPTO_NACL_KEYBYTES + sizeof(chakaPubInfo.clientNonce)];
	uint8_t serverPresponse[CRYPT_NACL_HASHBYTES * 2];
	uint8_t serverResponse[CRYPT_NACL_HASHBYTES];
	memcpy(serverResponseMaterial, chakaPubInfo.clientPublicKey, CRYPTO_NACL_KEYBYTES);
	*(uint64_t *)(serverResponseMaterial + CRYPTO_NACL_KEYBYTES) = chakaPubInfo.clientNonce;
	// we're definitely sure that the length of serverResponseMaterial is some multiplication of 8-octect
	for (register int i = 0; i < sizeof(serverResponseMaterial) / sizeof(chakaPubInfo.serverRandom); i++)
	{
		((uint64_t *)serverResponseMaterial)[i] ^= chakaPubInfo.serverRandom;
	}

	CryptoNaClHash(serverPresponse + CRYPT_NACL_HASHBYTES, serverResponseMaterial, sizeof(serverResponseMaterial));
	memcpy(serverPresponse, passwordHash, CRYPT_NACL_HASHBYTES);
	CryptoNaClHash(serverResponse, serverPresponse, sizeof(serverPresponse));

	memcpy(chakaPubInfo.salt, salt, sizeof(salt));	// should read from database
	// TODO: NotifyOrReturn might be NULL!
	WriteTo(h, chakaPubInfo.salt, sizeof(chakaPubInfo.salt) + sizeof(chakaPubInfo.serverNonce) + sizeof(chakaPubInfo.serverRandom), 0, NULL);
	WriteTo(h, serverResponse, sizeof(serverResponse), EOF, onServerResponseSent);
}




static void FSPAPI onServerResponseSent(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	ReadFrom(h, chakaPubInfo.peerResponse, sizeof(chakaPubInfo.peerResponse), onClientResponseReceived);
}



//	S --> C, [in FSP's ACK_CONNECT_REQUEST]: /Welcome and identity of S/Public Key_S
//	C --> S, [in FSP's PERSIST, had better with EoT]: /Greeting and identity of C/Public Key_C/Timestamp_C
//	S --> C, [PERSIST]: the salt, Timestamp_S, Random_S, S's response to the C's challenge
//		Suppose salted_password = HASH(salt | registered password)
//		Response: HASH(salted_password | HASH((C's public key, C's timestamp) XOR S's random(repeated))))
//	[C get the shared secret]
// *C --> S, [PERSIST]: C's reponse to the S's challenge
//		Let salted_input_password = HASH(salt | inputted password)
//		Reponse: HASH(salted_input_password | HASH((S's public key, S's timestamp) XOR S's random(repeated)))
// *[S get the shared secret]
//
//
// Validate the client's response, write back the Simple Artcrafted Web Site description file
//...
static void FSPAPI onClientResponseReceived(FSPHANDLE h, FSP_ServiceCode c, int r)
{
	// TODO: the client should precheck validity of nonce. If clock 'difference is too high'(?), reject the request
	// The client check the response of the server
	ALIGN(8)
	uint8_t clientResponseMaterial[CRYPTO_NACL_KEYBYTES + sizeof(chakaPubInfo.serverNonce)];
	uint8_t expectedPresponse[CRYPT_NACL_HASHBYTES * 2];
	uint8_t expectedResponse[CRYPT_NACL_HASHBYTES];

	memcpy(clientResponseMaterial, chakaPubInfo.serverPublicKey, CRYPTO_NACL_KEYBYTES);
	*(uint64_t *)(clientResponseMaterial + CRYPTO_NACL_KEYBYTES) = (uint64_t)htobe64(chakaPubInfo.serverNonce);
	// we're definitely sure that the length of clientResponseMaterial is some multiplication of 8-octect
	for (register int i = 0; i < sizeof(clientResponseMaterial) / sizeof(chakaPubInfo.serverRandom); i++)
	{
		((uint64_t *)clientResponseMaterial)[i] ^= chakaPubInfo.serverRandom;
	}
	CryptoNaClHash(expectedPresponse + CRYPT_NACL_HASHBYTES, clientResponseMaterial, sizeof(clientResponseMaterial));
	memcpy(expectedPresponse, passwordHash, CRYPT_NACL_HASHBYTES);
	CryptoNaClHash(expectedResponse, expectedPresponse, sizeof(expectedPresponse));

	r = memcmp(expectedResponse, chakaPubInfo.peerResponse, CRYPT_NACL_HASHBYTES);
	if(r != 0)
	{
		Dispose(h);
		return;
	}
	// TODO: write back the Mark down file!
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
