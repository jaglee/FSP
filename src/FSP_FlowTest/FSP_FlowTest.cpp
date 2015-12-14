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

	socket.InstallEphemeralKey();
	socketR2.InstallEphemeralKey();

	//
	socket.SetPairOfFiberID(nearFID, htobe32(LAST_WELL_KNOWN_ALFID));
	socketR2.SetPairOfFiberID(htobe32(LAST_WELL_KNOWN_ALFID), nearFID);

	socket.SetIntegrityCheckCode(& storage.hdr);

	storage2 = storage;

	bool checked = socketR2.ValidateICC(& storage2.hdr);
	assert(checked);

	storage2.payload[0] ^= 1;
	checked = socketR2.ValidateICC(& storage2.hdr);
	assert(checked);	// Because in CRC mode we doesn't care about the payload

	* ((uint8_t *) & storage2.hdr) ^= 1;
	checked = socketR2.ValidateICC(& storage2.hdr);
	assert(! checked);	// CRC64 could figure out burst of 64 bits error

	* ((uint8_t *) & storage2.hdr) ^= 1;
	checked = socketR2.ValidateICC(& storage2.hdr);
	assert(checked);
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
	DumpNetworkUInt16((uint16_t *)  & pCBR->connectParams, FSP_MAX_KEY_SIZE / 2);

	pSCB->SetSendWindowWithHeadReserved(FIRST_SN);
	socket.SetPairOfFiberID(nearFID, htobe32(LAST_WELL_KNOWN_ALFID));
	socket.InstallEphemeralKey();	// initializtion
	socket.InstallSessionKey(samplekey);

	pCBR->SetRecvWindowHead(FIRST_SN);
	socketR2.SetPairOfFiberID(htobe32(LAST_WELL_KNOWN_ALFID), nearFID);
	socketR2.InstallEphemeralKey();	// initializtion
	pCBR->recvWindowNextSN++;		// == FIRST_SN + 1
	socketR2.InstallSessionKey(samplekey);

	// So, the packet with FIRST_SN shall be calculated with CRC64
	// firstly, test recorded CRC mode
	// packet with sequence number less than FIRST_SN should be applied with CRC64
	FSP_NormalPacketHeader &request = storage.hdr;
	request.hs.Set<FSP_NormalPacketHeader, PURE_DATA>();

	request >>= FIRST_SN;
	socket.SetIntegrityCheckCode(& request);
	//
	bool checked = socketR2.ValidateICC(& request);
	assert(checked);

	request >>= FIRST_SN - 1;
	socket.SetIntegrityCheckCode(& request);
	//
	checked = socketR2.ValidateICC(& request);
	assert(checked);

	// should apply AES-GCM
	request >>= FIRST_SN + 1;
	socket.SetIntegrityCheckCode(& request);
	//
	checked = socketR2.ValidateICC(& request);
	assert(checked);

	// partially scattered I/O
	// make it a gap of one qword
	BYTE *payload = (BYTE *) & request + sizeof(FSP_NormalPacketHeader) + 8;
	socket.SetIntegrityCheckCode(& request, payload, 9);	// arbitrary length in the stack
	checked = socketR2.ValidateICC(& request, 9);
	assert(!checked);	// because of the gap

	// continuous calculation of ICC should not have negative effect 
	void *cipherText;
	socket.SetIntegrityCheckCode(& request, payload, 19);
	cipherText = socket.SetIntegrityCheckCode(& request, payload, 21);
	memcpy(payload, cipherText, 21);

	memcpy(& storage2, & storage, sizeof(FSP_NormalPacketHeader));
	memcpy(storage2.payload, & storage.payload[8], sizeof(FSP_NormalPacketHeader));	// make received 'solidified'

	storage2.payload[0] ^= 1;
	checked = socketR2.ValidateICC(& storage2.hdr, 21);
	assert(!checked);

	storage2.payload[0] ^= 1;
	checked = socketR2.ValidateICC(& storage2.hdr, 21);
	assert(checked);

	memcpy(& storage3, & storage, sizeof(FSP_NormalPacketHeader) + 21);
	checked = socketR2.ValidateICC(& storage3.hdr, 21);
	assert(!checked);	// because of the gap

	memcpy(storage3.payload, & storage.payload[8], 21);
	checked = socketR2.ValidateICC(& storage3.hdr, 21);
	assert(checked);

	// Merge the KEEP_ALIVE packet testing...
	// It's most complicated in the sense that 
	ControlBlock::PFSP_SocketBuf skb1 = socketR2.AllocRecvBuf(FIRST_SN + 1);
	skb1->SetFlag<IS_FULFILLED>();

	// See also: timer.cpp::KeepAlive
	ControlBlock::seq_t seq0;
	FSP_PreparedKEEP_ALIVE buf;
	int sizeSNACK = socketR2.GenerateSNACK(buf, seq0);
	uint32_t salt = buf.ackTime;
	printf_s("Size of the SNACK header = %d, expected SN = %u, salt=0x%X\n", sizeSNACK, seq0, salt);

	buf.hdr.hs.Set<KEEP_ALIVE>(sizeof(FSP_NormalPacketHeader) + sizeSNACK);
	pSCB->SetSequenceFlags(& buf.hdr, seq0);
	//
	socketR2.SetIntegrityCheckCode(& buf.hdr, NULL, 0, salt);

	checked = socket.ValidateICC(& buf.hdr, 0, salt);
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


/**
 * 
 */
int _tmain(int argc, _TCHAR* argv[])
{
	FlowTestAcknowledge();
	FlowTestRetransmission();

	//UnitTestCRC();
	//UnitTestICC();

	//TrySRP6();
	//UnitTestTweetNacl();
	//
	// TODO: UnitTest of SendInplace, SendStream

	return 0;
}
