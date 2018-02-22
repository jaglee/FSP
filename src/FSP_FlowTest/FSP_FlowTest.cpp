// FSP_FlowTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

void UnitTestCRC()
{
	const ALFID_T nearFID = 4321;
	struct
	{
		ALIGN(MAC_ALIGNMENT) FSP_NormalPacketHeader	hdr;
		BYTE	payload[40];
	} storage, storage2;
	CSocketItemExDbg socket;
	CSocketItemExDbg socketR2;

	ControlBlock *pCB2 = socketR2.GetControlBlock();
	ControlBlock *pCB = socket.GetControlBlock();
	for(register int i = 0; i < sizeof(pCB->connectParams); i++)
	{
		((uint8_t *) & pCB->connectParams)[i] = i;
		((uint8_t *) & pCB2->connectParams)[i] = i;
	}
	for (register int i = 0; i < sizeof(storage.payload); i++)
	{
		storage.payload[i] = (BYTE)i;
	}
	socket.InstallEphemeralKey();
	socketR2.InstallEphemeralKey();

	//
	socket.SetPairOfFiberID(nearFID, htobe32(LAST_WELL_KNOWN_ALFID));
	socketR2.SetPairOfFiberID(htobe32(LAST_WELL_KNOWN_ALFID), nearFID);
	storage.hdr.hs.hsp = htobe16(sizeof(FSP_NormalPacketHeader));
	socket.SetIntegrityCheckCode(& storage.hdr);

	storage2 = storage;

	bool checked = socketR2.ValidateICC(& storage2.hdr, 0, nearFID, 0);
	assert(checked);

	storage2.payload[0] ^= 1;
	checked = socketR2.ValidateICC(& storage2.hdr, 0, nearFID, 0);
	assert(checked);	// Because payload length is set to zero in the parameter

	* ((uint8_t *) & storage2.hdr) ^= 1;
	checked = socketR2.ValidateICC(& storage2.hdr, 0, nearFID, 0);
	assert(! checked);	// CRC64 could figure out burst of 64 bits error

	* ((uint8_t *) & storage2.hdr) ^= 1;
	checked = socketR2.ValidateICC(& storage2.hdr, 0, nearFID, 0);
	assert(checked);

	// Assume the payload is of 3 octets
	socket.SetIntegrityCheckCode(&storage.hdr, storage.payload, 3);
	storage2 = storage;

	checked = socketR2.ValidateICC(&storage2.hdr, 3, nearFID, 0);
	assert(checked);

	storage2.payload[0] ^= 1;
	checked = socketR2.ValidateICC(&storage2.hdr, 3, nearFID, 0);
	assert(! checked);
}



/**
 *
 */
void UnitTestICC()
{
	static const ControlBlock::seq_t FIRST_SN = 12;
	const ALFID_T nearFID = 4321;
	struct
	{
		ALIGN(MAC_ALIGNMENT) FSP_NormalPacketHeader	hdr;
		BYTE	payload[40];
	} storage, storage2, storage3;
	BYTE samplekey[16] = { 0, 0xB1, 0xC2, 3, 4, 5, 6, 7, 8, 0xD9, 10, 11, 12, 13, 14, 15 };
	CSocketItemExDbg socket;
	CSocketItemExDbg socketR2;
	ControlBlock *pSCB = socket.GetControlBlock();
	ControlBlock *pCBR = socketR2.GetControlBlock();

	memset(& storage, 1, sizeof(storage));
	memset(& storage2, 2, sizeof(storage2));

	// emulate negotiation of sequence number and the session key
	rand_w32((uint32_t *) & pSCB->connectParams, FSP_MAX_KEY_SIZE / 4);	// 256 bits
	memcpy(& pCBR->connectParams, & pSCB->connectParams, FSP_MAX_KEY_SIZE);	// 256 bits
	//^when install session key the original connection parameter is destroyed
	// so it must be copied beforehand
	printf_s("\nEphemeral master key generated: \n");
	DumpNetworkUInt16((uint16_t *) & pCBR->connectParams, FSP_MAX_KEY_SIZE / 2);

	pSCB->SetSendWindow(FIRST_SN);
	socket.SetPairOfFiberID(nearFID, htobe32(LAST_WELL_KNOWN_ALFID));
	socket.InstallEphemeralKey();	// initializtion
	socket.InstallSessionKey(samplekey);

	pCBR->SetRecvWindow(FIRST_SN);
	socketR2.SetPairOfFiberID(htobe32(LAST_WELL_KNOWN_ALFID), nearFID);
	socketR2.InstallEphemeralKey();	// initializtion
	socketR2.InstallSessionKey(samplekey);

	// So, the packet with FIRST_SN shall be calculated with CRC64
	// firstly, test recorded CRC mode
	// packet with sequence number less than FIRST_SN should be applied with CRC64
	FSP_NormalPacketHeader &request = storage.hdr;
	request.hs.Set<FSP_NormalPacketHeader, PURE_DATA>();

	request.sequenceNo = htobe32(FIRST_SN);
	socket.SetIntegrityCheckCode(& request);
	//
	bool checked = socketR2.ValidateICC(& request, 0, nearFID, 0);
	assert(checked);

	request.sequenceNo = htobe32(FIRST_SN - 1);
	socket.SetIntegrityCheckCode(& request);
	//
	checked = socketR2.ValidateICC(& request, 0, nearFID, 0);
	assert(checked);

	// should apply AES-GCM
	request.sequenceNo = htobe32(FIRST_SN + 1);
	socket.SetIntegrityCheckCode(& request);
	//
	checked = socketR2.ValidateICC(& request, 0, nearFID, 0);
	assert(checked);

	// The sender should not rekey, but the receiver should prepare:
	request.sequenceNo = htobe32(FIRST_SN + FSP_REKEY_THRESHOLD - 1);
	socket.SetIntegrityCheckCode(&request);
	//
	checked = socketR2.ValidateICC(&request, 0, nearFID, 0);
	assert(checked);

	// The sender should rekey while the receiver has prepared:
	request.sequenceNo = htobe32(FIRST_SN + FSP_REKEY_THRESHOLD);
	socket.SetIntegrityCheckCode(&request);
	//
	checked = socketR2.ValidateICC(&request, 0, nearFID, 0);
	assert(checked);

	// partially scattered I/O
	// make it a gap of one qword
	BYTE *payload = (BYTE *) & request + sizeof(FSP_NormalPacketHeader) + 8;
	socket.SetIntegrityCheckCode(& request, payload, 9);	// arbitrary length in the stack
	checked = socketR2.ValidateICC(& request, 9, nearFID, 0);
	assert(!checked);	// because of the gap

	// continuous calculation of ICC should not have negative effect 
	void *cipherText;
	socket.SetIntegrityCheckCode(& request, payload, 19);
	cipherText = socket.SetIntegrityCheckCode(& request, payload, 21);
	memcpy(payload, cipherText, 21);

	memcpy(& storage2, & storage, sizeof(FSP_NormalPacketHeader));
	memcpy(storage2.payload, & storage.payload[8], sizeof(FSP_NormalPacketHeader));	// make received 'solidified'

	storage2.payload[0] ^= 1;
	checked = socketR2.ValidateICC(& storage2.hdr, 21, nearFID, 0);
	assert(!checked);

	storage2.payload[0] ^= 1;
	checked = socketR2.ValidateICC(& storage2.hdr, 21, nearFID, 0);
	assert(checked);

	memcpy(& storage3, & storage, sizeof(FSP_NormalPacketHeader) + 21);
	checked = socketR2.ValidateICC(& storage3.hdr, 21, nearFID, 0);
	assert(!checked);	// because of the gap

	memcpy(storage3.payload, & storage.payload[8], 21);
	checked = socketR2.ValidateICC(& storage3.hdr, 21, nearFID, 0);
	assert(checked);

	// Merge the KEEP_ALIVE packet testing...
	// It's most complicated in the sense that 
	ControlBlock::PFSP_SocketBuf skb1 = socketR2.AllocRecvBuf(FIRST_SN + 1);
	skb1->SetFlag<IS_FULFILLED>();
	pCBR->recvWindowNextSN++;		// == FIRST_SN + 1

	// See also: timer.cpp::KeepAlive
	ControlBlock::seq_t seq0;
	struct
	{
		FSP_NormalPacketHeader hdr;
		FSP_PreparedKEEP_ALIVE buf;
	} mp;
	int sizeSNACK = socketR2.GenerateSNACK(mp.buf, seq0, sizeof(FSP_NormalPacketHeader));
	uint32_t salt = mp.buf.sentinel.serialNo;
	printf_s("Size of the SNACK header = %d, expected SN = %u, salt=0x%X\n", sizeSNACK, seq0, salt);

	mp.hdr.hs.Set(KEEP_ALIVE, sizeof(FSP_NormalPacketHeader) + sizeSNACK);
	// pSCB->SetSequenceFlags(& mp.hdr, FIRST_SN + FSP_REKEY_THRESHOLD);
	pSCB->SetSequenceFlags(& mp.hdr, FIRST_SN + 1);
	mp.hdr.expectedSN = htobe32(seq0);
	//
	socket.SetIntegrityCheckCode(& mp.hdr, NULL, 0, salt);

	checked = socketR2.ValidateICC(& mp.hdr, 0, socket.fidPair.source, salt);
	assert(checked);
	// assert(socket.fidPair.source == socketR2.fidPair.peer);
}



void UnitTestHMAC()
{
	static const ControlBlock::seq_t FIRST_SN = 12;
	const ALFID_T nearFID = 4321;
	struct
	{
		ALIGN(MAC_ALIGNMENT) FSP_NormalPacketHeader	hdr;
		BYTE	payload[40];
	} storage, storage2, storage3;
	BYTE samplekey[16] = { 0, 0xB1, 0xC2, 3, 4, 5, 6, 7, 8, 0xD9, 10, 11, 12, 13, 14, 15 };
	CSocketItemExDbg socket;
	CSocketItemExDbg socketR2;
	ControlBlock *pSCB = socket.GetControlBlock();
	ControlBlock *pCBR = socketR2.GetControlBlock();

	for (register int i = 0; i < sizeof(storage.payload); i++)
	{
		storage.payload[i] = (BYTE)('0' + i);
		storage2.payload[i] = (BYTE)('A' + i);
	}

	// HMAC only
	pSCB->noEncrypt = 1;
	pCBR->noEncrypt = 1;

	// emulate negotiation of sequence number and the session key
	rand_w32((uint32_t *)& pSCB->connectParams, FSP_MAX_KEY_SIZE / 4);		// 256 bits
	memcpy(&pCBR->connectParams, &pSCB->connectParams, FSP_MAX_KEY_SIZE);	// 256 bits
	DumpNetworkUInt16((uint16_t *)& pCBR->connectParams, FSP_MAX_KEY_SIZE / 2);

	pSCB->SetSendWindow(FIRST_SN);
	socket.SetPairOfFiberID(nearFID, htobe32(LAST_WELL_KNOWN_ALFID));
	socket.InstallEphemeralKey();	// initializtion
	socket.InstallSessionKey(samplekey);

	pCBR->SetRecvWindow(FIRST_SN);
	socketR2.SetPairOfFiberID(htobe32(LAST_WELL_KNOWN_ALFID), nearFID);
	socketR2.InstallEphemeralKey();	// initializtion
	pCBR->recvWindowNextSN++;		// == FIRST_SN + 1
	socketR2.InstallSessionKey(samplekey);

	// So, the packet with FIRST_SN shall be calculated with CRC64
	// firstly, test recorded CRC mode
	// packet with sequence number less than FIRST_SN should be applied with CRC64
	FSP_NormalPacketHeader &request = storage.hdr;
	request.hs.Set<FSP_NormalPacketHeader, PURE_DATA>();

	request.sequenceNo = FIRST_SN;
	socket.SetIntegrityCheckCode(&request);
	//
	bool checked = socketR2.ValidateICC(&request, 0, nearFID, 0);
	assert(checked);

	request.sequenceNo = FIRST_SN - 1;
	socket.SetIntegrityCheckCode(&request);
	//
	checked = socketR2.ValidateICC(&request, 0, nearFID, 0);
	assert(checked);

	// should apply BLAKE2
	request.sequenceNo = FIRST_SN + 1;
	socket.SetIntegrityCheckCode(&request);
	//
	checked = socketR2.ValidateICC(&request, 0, nearFID, 0);
	assert(checked);

	// partially scattered I/O
	// make it a gap of one qword
	BYTE *payload = (BYTE *)& request + sizeof(FSP_NormalPacketHeader) + 8;
	socket.SetIntegrityCheckCode(&request, payload, 9);	// arbitrary length in the stack
	checked = socketR2.ValidateICC(&request, 9, nearFID, 0);
	assert(!checked);	// because of the gap

	// continuous calculation of ICC should not have negative effect 
	void *buf;
	socket.SetIntegrityCheckCode(&request, payload, 19);
	buf = socket.SetIntegrityCheckCode(&request, payload, 21);
	assert(buf == payload);	// AH only

	memcpy(&storage2, &storage, sizeof(FSP_NormalPacketHeader));
	memcpy(storage2.payload, &storage.payload[8], sizeof(FSP_NormalPacketHeader));	// make received 'solidified'

	storage2.payload[0] ^= 1;
	checked = socketR2.ValidateICC(&storage2.hdr, 21, nearFID, 0);
	assert(!checked);

	storage2.payload[0] ^= 1;
	checked = socketR2.ValidateICC(&storage2.hdr, 21, nearFID, 0);
	assert(checked);

	memcpy(&storage3, &storage, sizeof(FSP_NormalPacketHeader) + 21);
	checked = socketR2.ValidateICC(&storage3.hdr, 21, nearFID, 0);
	assert(!checked);	// because of the gap

	memcpy(storage3.payload, &storage.payload[8], 21);
	checked = socketR2.ValidateICC(&storage3.hdr, 21, nearFID, 0);
	assert(checked);

	// Merge the KEEP_ALIVE packet testing...
	// It's most complicated in the sense that 
	ControlBlock::PFSP_SocketBuf skb1 = socketR2.AllocRecvBuf(FIRST_SN + 1);
	skb1->SetFlag<IS_FULFILLED>();

	// See also: timer.cpp::KeepAlive
	ControlBlock::seq_t seq0;
	struct
	{
		FSP_NormalPacketHeader hdr;
		FSP_PreparedKEEP_ALIVE buf;
	} mp;
	int sizeSNACK = socketR2.GenerateSNACK(mp.buf, seq0, sizeof(FSP_NormalPacketHeader));
	uint32_t salt = mp.buf.sentinel.serialNo;
	printf_s("Size of the SNACK header = %d, expected SN = %u, salt=0x%X\n", sizeSNACK, seq0, salt);

	mp.hdr.hs.Set(KEEP_ALIVE, sizeof(FSP_NormalPacketHeader) + sizeSNACK);
	pSCB->SetSequenceFlags(&mp.hdr, pSCB->sendWindowNextSN);
	mp.hdr.expectedSN = htobe32(seq0);
	//
	socketR2.SetIntegrityCheckCode(&mp.hdr, NULL, 0, salt);

	checked = socket.ValidateICC(&mp.hdr, 0, socketR2.fidPair.source, salt);
	assert(checked);

	checked = socket.ValidateICC(&mp.hdr, 0, socket.fidPair.peer, salt);
	assert(checked);
}



void UnitTestTweetNacl()
{
	// the default welcome message, with CYRPTO_NACL_KEYBYTES (32 bytes, 256 bits) place holder for the static public key
	const char *defaultWelcome = "File synchronizer based on Flexible Session Protocol, version 0.1";
	static unsigned char bufPrivateKeyAlice[CRYPTO_NACL_KEYBYTES];
	//
	unsigned short mLen = (unsigned short)strlen(defaultWelcome) + 1;
	unsigned char *thisWelcome = (unsigned char *)_alloca(mLen + CRYPTO_NACL_KEYBYTES);
	memcpy(thisWelcome, defaultWelcome, mLen);	//+\000012345678901234567890123456789012

	unsigned char *bufPublicKeyAlice = (unsigned char *)thisWelcome + mLen;
	CryptoNaClKeyPair(bufPublicKeyAlice, bufPrivateKeyAlice);

	printf("The internal private key of Alice:\n");
	DumpNetworkUInt16((uint16_t *)bufPrivateKeyAlice, CRYPTO_NACL_KEYBYTES / 2);

	printf("The public key of Alice:\n");
	DumpNetworkUInt16((uint16_t *)bufPublicKeyAlice, CRYPTO_NACL_KEYBYTES / 2);

	//
	// peer's first message is placed into welcome part of the ctx
	unsigned char bufPublicKeyBob[CRYPTO_NACL_KEYBYTES];
	unsigned char bufPrivateKeyBob[CRYPTO_NACL_KEYBYTES];
	CryptoNaClKeyPair(bufPublicKeyBob, bufPrivateKeyBob);

	printf("The public key of Bob:\n");
	DumpNetworkUInt16((uint16_t *)bufPublicKeyBob, CRYPTO_NACL_KEYBYTES / 2);
	printf("The internal private key of Bob:\n");
	DumpNetworkUInt16((uint16_t *)bufPrivateKeyBob, CRYPTO_NACL_KEYBYTES / 2);

	unsigned char bufSharedKey[CRYPTO_NACL_KEYBYTES];
	CryptoNaClGetSharedSecret(bufSharedKey, bufPublicKeyAlice, bufPrivateKeyBob);

	printf("The shared secret rendered by Bob:\n");
	DumpNetworkUInt16((uint16_t *)bufSharedKey, CRYPTO_NACL_KEYBYTES / 2);

	CryptoNaClGetSharedSecret(bufSharedKey, bufPublicKeyBob, bufPrivateKeyAlice);
	printf("The shared secret rendered by Alice:\n");
	DumpNetworkUInt16((uint16_t *)bufSharedKey, CRYPTO_NACL_KEYBYTES / 2);
}

#include <pshpack1.h>
struct FREWS
{
	uint32_t	adRecvWS : 24;
	uint32_t	flags : 8;
};
struct FSP_FixedHeader
{
	uint32_t		sequenceNo;
	uint32_t		expectedSN;
	union
	{
		uint64_t	 code;	// ICC
		struct
		{
			uint32_t source;
			uint32_t peer;
		} id;
	} integrity;
	//
	struct FREWS frews;
	//
	uint8_t		version;
	uint8_t		opCode;		// Operation Code
	uint16_t	hsp;		// Header Stack Pointer
};
#include <poppack.h>

void UnitTestByteOrderDefinitin()
{
	$FSP_HeaderSignature fhs;
	uint32_t & rFHS = *(uint32_t *)& fhs;

	fhs.opCode = _FSP_Operation_Code(1);
	fhs.major = 0;
	fhs.hsp = 0;

	printf_s("FHS = %08x\n", rFHS);	// 01 00 00 00 

	fhs.opCode = (_FSP_Operation_Code)2;
	fhs.major = 1;
	fhs.hsp = 0x303;

	printf_s("FHS = %08x\n", rFHS);	// 02 01 03 03

	FSP_FixedHeader fh;
	printf_s("size of fixed header: %d\n", sizeof(fh)); // 24

	fh.frews.flags = 1;
	fh.frews.adRecvWS = 2;
	printf_s("Frews = %08x\n", *(uint32_t *)& fh.frews);	// 0x01000002
}

/**
 * 
 */
int _tmain(int argc, _TCHAR* argv[])
{
	FlowTestAcknowledge();
	FlowTestRetransmission();
	FlowTestRecvWinRoundRobin();

	UnitTestCRC();
	UnitTestICC();
	UnitTestHMAC();

	TrySRP6();
	UnitTestTweetNacl();
	TryCHAKA();
	TryWideChar();
	UnitTestByteOrderDefinitin();

	CompareMemoryPattern("$memory.^");

	return 0;
}
