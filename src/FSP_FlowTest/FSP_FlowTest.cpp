// FSP_FlowTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


static const ControlBlock::seq_t FIRST_SN = 12;
static const int MAX_GAPS_NUM = 2;
static const int MAX_BLOCK_NUM = 16;


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
	socket.SetIntegrityCheckCode(& request, payload, 19);
	socket.SetIntegrityCheckCode(& request, payload, 21);

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


/**
 * Emulate acknowledgement
 */
void FlowTestAcknowledge()
{
	CSocketItemExDbg socket(MAX_BLOCK_NUM, MAX_BLOCK_NUM);
	ControlBlock *pSCB = socket.GetControlBlock();
	FSP_SelectiveNACK::GapDescriptor gaps[MAX_GAPS_NUM + 1];
	// the last descriptor place holder is for the sentinel/tail gap descriptor appended later

	pSCB->welcomedNextSNtoSend = pSCB->sendWindowFirstSN = FIRST_SN;
	pSCB->sendBufferNextSN = pSCB->sendWindowNextSN = FIRST_SN + 1;
	// Pretend that the first packet has been sent and is waiting acknowledgement...
	int r = socket.RespondToSNACK(FIRST_SN + 1, NULL, 0);
	assert(r == 1 && pSCB->sendBufferNextSN == pSCB->sendWindowFirstSN);
	assert(pSCB->sendWindowFirstSN == FIRST_SN + 1);
	assert(pSCB->sendWindowNextSN == FIRST_SN + 1);

	pSCB->SetSendWindowWithHeadReserved(FIRST_SN);
	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadSend();
	//Assert::IsNotNull(skb);
	assert(pSCB->sendWindowSize == 1);	// set by GetVeryFirstSendBuf
	assert(pSCB->sendBufferNextSN == FIRST_SN + 1);
	skb->SetFlag<IS_COMPLETED>();
	skb->Lock();

	skb = pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	skb->Lock();
	pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	skb->Lock();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 3);

	// A NULL acknowledgement, Keep-Alive
	r = socket.RespondToSNACK(FIRST_SN, NULL, 0);
	assert(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN);

	// emulate sending, assume 3 packets sent
	pSCB->sendWindowNextSN += 3;
	pSCB->sendWindowSize = MAX_BLOCK_NUM;	// don't let size of send window limit the test
	assert(pSCB->sendWindowNextSN == FIRST_SN + 3);

	// acknowledge the first two
	r = socket.RespondToSNACK(FIRST_SN + 2, NULL, 0);
	assert(r == 2 && pSCB->sendWindowFirstSN == FIRST_SN + 2);
	assert(pSCB->CountUnacknowledged() >= 0);
	assert(pSCB->sendWindowSize == MAX_BLOCK_NUM - 2);

	// Now, more test...
	for(int i = 3; i < MAX_BLOCK_NUM; i++)
	{
		skb = pSCB->GetSendBuf();
		assert(skb != NULL);
		skb->SetFlag<IS_COMPLETED>();
		skb->Lock();
	}
	pSCB->sendWindowNextSN += MAX_BLOCK_NUM - 3;
	assert(pSCB->sendWindowNextSN == FIRST_SN + MAX_BLOCK_NUM);

	// All buffer blocks should have been consumed after the two acknowledged have been allocated
	// [however, sendWindowSize is not reduced yet]
	skb = pSCB->GetSendBuf();	// the two acknowledged
	skb->SetFlag<IS_COMPLETED>();
	skb = pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	skb = pSCB->GetSendBuf();	// no space in the send buffer.
	assert(skb == NULL);
	assert(pSCB->sendWindowSize == MAX_BLOCK_NUM - 2);

	// assume the third is a gap...
	gaps[0].dataLength = htobe32(1);
	gaps[0].gapWidth = htobe32(1);
	//// this is an illegal one	// now it is perfectly OK
	//r = socket.RespondToSNACK(FIRST_SN, gaps, 1);
	//assert(r == -EBADF && pSCB->sendWindowFirstSN == FIRST_SN + 2);
	//assert(pSCB->CountUnacknowledged() >= 0);
	//// again, an outdated one
	//r = socket.RespondToSNACK(FIRST_SN + 2, gaps, 1);
	//assert(r == -EDOM && pSCB->sendWindowFirstSN == FIRST_SN + 2);
	//assert(pSCB->CountUnacknowledged() >= 0);

	// this is a legal one: the first two has been acknowledged; the 3rd and the 5th is to be acknowledged
	r = socket.RespondToSNACK(FIRST_SN + 3, gaps, 1);
	assert(r == 2 && pSCB->sendWindowFirstSN == FIRST_SN + 3);
	assert(pSCB->CountUnacknowledged() >= 0);

	// this is a legal but one gap is redundant, one is additional
	gaps[0].dataLength = htobe32(1);
	gaps[0].gapWidth = htobe32(1);
	gaps[1].dataLength = htobe32(1);
	gaps[1].gapWidth = htobe32(1);
	r = socket.RespondToSNACK(FIRST_SN + 3, gaps, 2);
	assert(r == 1 && pSCB->sendWindowFirstSN == FIRST_SN + 3);
	assert(pSCB->CountUnacknowledged() >= 0);

	// two gaps, overlap with previous one [only to urge retransmission of those negatively acknowledged]
	gaps[0].dataLength = htobe32(1);
	gaps[0].gapWidth = htobe32(1);
	gaps[1].dataLength = htobe32(1);
	gaps[1].gapWidth = htobe32(1);
	r = socket.RespondToSNACK(FIRST_SN + 3, gaps, 2);
	assert(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 3);
	assert(pSCB->CountUnacknowledged() >= 0);

	// two gaps, do real new acknowledgement: the 4th (the 5th has been acknowledged) and the 7th
	gaps[0].dataLength = htobe32(1);
	gaps[0].gapWidth = htobe32(1);
	gaps[1].dataLength = htobe32(1);
	gaps[1].gapWidth = htobe32(1);
	r = socket.RespondToSNACK(FIRST_SN + 5, gaps, 2);
	assert(r == 2 && pSCB->sendWindowFirstSN == FIRST_SN + 5);
	assert(pSCB->CountUnacknowledged() >= 0);

#if 0
	static const int MAX_BLOCK_NUM_L = 0x20000;	// 65536 * 2
	// a very large continuous data segment is acknowledged
	gaps[0].dataLength = htobe32(1);
	gaps[0].gapWidth = htobe32(1);
	gaps[1].dataLength = htobe32(1);
	gaps[1].gapWidth = htobe32(1);
	r = socket.RespondToSNACK(FIRST_SN + 0x1000A, gaps, 2);
	assert(r == 0x1000A - 5 && pSCB->sendWindowFirstSN == FIRST_SN + 0x1000A);
	assert(pSCB->sendWindowSize == MAX_BLOCK_NUM_L - 0x1000A);
	assert(pSCB->CountUnacknowledged() >= 0);

	// Test round-robin...
	for(int i = MAX_BLOCK_NUM_L + 2; i < MAX_BLOCK_NUM_L + 0x10000; i++)
	{
		skb = pSCB->GetSendBuf();
		assert(skb != NULL);
		skb->SetFlag<IS_COMPLETED>();
		skb->Lock();
	}
	pSCB->sendWindowNextSN += 0x10000;	// queuing to send is not the same as sending

	// an even larger continuous data segment is acknowledged
	gaps[0].dataLength = htobe32(1);
	gaps[0].gapWidth = htobe32(1);
	gaps[1].dataLength = htobe32(1);
	gaps[1].gapWidth = htobe32(1);
	r = socket.RespondToSNACK(FIRST_SN + MAX_BLOCK_NUM_L + 0xF000, gaps, 2);
	assert(r ==  MAX_BLOCK_NUM_L + 0xF000 - 0x1000A && pSCB->sendWindowHeadPos == 0xF000);
	assert(pSCB->sendWindowSize == - 0xF000);	// overflow, but don't care!
	assert(pSCB->sendWindowFirstSN == FIRST_SN + MAX_BLOCK_NUM_L + 0xF000);
	assert(pSCB->CountUnacknowledged() >= 0);
#endif
}


//// TODO: explicity remove/avoid congest control at the session layer
//void UnitTestCongestControl()
//{
//	CubicRateControl ctrlRate;
//	//
//	ctrlRate.Reset();
//	//
//	ctrlRate.AdditiveIncrease(NowUTC(), 1);
//	Sleep(1000);
//	ctrlRate.AdditiveIncrease(NowUTC(), 2000);
//	Sleep(2000);
//	ctrlRate.OnCongested();
//	Sleep(1000);
//	ctrlRate.AdditiveIncrease(NowUTC(), 2000);
//	//
//}


void PrepareFlowTestResend(CSocketItemExDbg & dbgSocket, PControlBlock & pSCB)
{
	int memsize = sizeof(ControlBlock) + (sizeof ControlBlock::FSP_SocketBuf + MAX_BLOCK_SIZE) * 8;
	memset(& dbgSocket, 0, sizeof(CSocketItemExDbg));
	dbgSocket.dwMemorySize = memsize;

	pSCB = (ControlBlock *)malloc(dbgSocket.dwMemorySize);
	dbgSocket.pControlBlock = pSCB;

	pSCB->Init((memsize - sizeof(ControlBlock)) / 2, (memsize - sizeof(ControlBlock)) / 2);

	// set the begin of the send sequence number for the test to work properly
	// set the negotiated receive window parameter
	pSCB->recvWindowFirstSN = pSCB->recvWindowNextSN = FIRST_SN;

	pSCB->SetSendWindowWithHeadReserved(FIRST_SN);
	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadSend();
	skb->SetFlag<IS_COMPLETED>();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 1);

	skb = pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 2);

	skb = pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 3);

	skb = pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 4);

	skb = pSCB->GetSendBuf();
	assert(skb == NULL);	// as we knew there're only 4 packet slots 

	++(pSCB->sendWindowNextSN);

	++(pSCB->sendWindowNextSN);

	++(pSCB->sendWindowNextSN);

	++(pSCB->sendWindowNextSN);

	skb = pSCB->HeadSend();

	// emulate received the first data packet
	ControlBlock::PFSP_SocketBuf skb5 = pSCB->AllocRecvBuf(FIRST_SN);
	assert(skb5 != NULL);
	skb5->SetFlag<IS_FULFILLED>();

	// emulate a received message that crosses two packet
	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 1);
	assert(skb5 != NULL);
	assert(pSCB->recvWindowNextSN == FIRST_SN + 2);

	skb5->SetFlag<IS_FULFILLED>();

	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 3);
	assert(skb5 != NULL);
	assert(pSCB->recvWindowNextSN == FIRST_SN + 4);

	skb5->SetFlag<IS_FULFILLED>();

	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 4);
	assert(skb5 == NULL);	// No more space in the receive buffer
}





/**
 * Emulate acknowledgement
 */
/**
 * Unit Test of:
 * GetSendBuf
 * AllocRecvBuf
 * GetSelectiveNACK
 * RespondToSNACK
 */
void FlowTestRetransmission()
{
	CSocketItemExDbg dbgSocket;
	PControlBlock pSCB;
	
	PrepareFlowTestResend(dbgSocket, pSCB);

	// what is the content of the selective negative acknowledgement?
	// See also CSocketItemEx::SendSNACK
	PktBufferBlock pktBuffer;
	FSP_PreparedKEEP_ALIVE & buf = *(FSP_PreparedKEEP_ALIVE *) & pktBuffer.hdr;
	ControlBlock::seq_t seq4;
	int32_t len = dbgSocket.GenerateSNACK(buf, seq4);
	len += sizeof(FSP_NormalPacketHeader);

	buf.hdr.hs.version = THIS_FSP_VERSION;
	buf.hdr.hs.opCode = KEEP_ALIVE;
	buf.hdr.hs.hsp = htobe16(uint16_t(len));

	// Both KEEP_ALIVE and ACK_FLUSH are payloadless out-of-band control block which always apply current session key
	// See also ControlBlock::SetSequenceFlags
	buf.hdr.sequenceNo = htobe32(pSCB->sendWindowNextSN - 1);
	buf.hdr.expectedSN = htobe32(seq4);
	buf.hdr.ClearFlags();
	buf.hdr.SetRecvWS(pSCB->RecvWindowSize());

	dbgSocket.SetIntegrityCheckCode(& buf.hdr, NULL, 0, buf.GetSaltValue());

	// Firstly emulate receive the packet before emulate OnGetKeepAlive
	dbgSocket.headPacket = & pktBuffer;
	dbgSocket.headPacket->pktSeqNo = FIRST_SN + 3;
	dbgSocket.headPacket->lenData = 0;
	dbgSocket.tRoundTrip_us = 1;
	dbgSocket.tEarliestSend = NowUTC();
	dbgSocket.tRecentSend = dbgSocket.tEarliestSend + 1;

	// See also CSocketItemEx::OnGetKeepAlive
	FSP_SelectiveNACK::GapDescriptor *snack;
	int n;
	ControlBlock::seq_t seq5;
	dbgSocket.ValidateSNACK(seq5, snack, n);

	assert(seq5 == seq4 && n == 1);

	dbgSocket.RespondToSNACK(seq5, snack, n);

	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadSend();
	assert(skb->flags == 0);	// GetFlag<IS_ACKNOWLEDGED>()
	assert((skb + 1)->flags == 0);	// GetFlag<IS_ACKNOWLEDGED>()
	assert((skb + 3)->GetFlag<IS_ACKNOWLEDGED>());
	assert(dbgSocket.GetControlBlock()->sendWindowFirstSN == FIRST_SN + 2);

	// TODO: Test round-robin, by slide one...
	// TODO: Test calculation of RTT and Keep alive timeout 
	// free(pSCB);	// clean up work done by the destroyer of CSocketItemExDbg
}



//SRP-6
//	I: identity /U
//	P: password	/w
//	s: salt		/S
//	v: verifier	// v = g^x, x = H(s, I, P)	/W
//
//	a, b are generated randomly
//	Client				Server
//		I		->	(lookup s, v)		// identity I, salt s; verifier v
//	x = H(s, I, P)		<-	(s)	
//	A = g^a			->	B = 3v + g^b	// RESTful: A together with I
//						u = H(A, B)
//	u = H(A, B)		<-(B, u)
//	S = (B - 3g^x)^(a + ux)				//== (g^b)^(a+ux) = g^b^a * g^b^(ux) = g^a * g^(ux))^b = (g^a*(g^x)^u)^b
//	M1 = H(A, B, S)		->
//						S = (Av^u)^b
//						verify M1
//	verify M2		<-	M2 = H(A, M1, S)
//	K = H(S)			K = H(S)
void TrySRP6()
{
	const unsigned int BITS_COUNT = 1536;
	const char *U = "FSP_FlowTest";
	const char *S = "FSP_Srv";
	const char *password = "Passw0rd";
	//
	mpz_t p;
	mpz_t g;
	mpz_t t;

	mpz_init_set_str(p, "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
		"29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
		"EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
		"E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
		"EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
		"C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
		"83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
		"670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"
		, 16);
	mpz_init_set_ui(g, 2);
	mpz_init(t);

	//	Client				Server
	//		I		->	(lookup s, v)	// identity I, salt s; verifier v
	//	x = H(s, I, P)		<-	(s)	
	mpz_class x;
	mpz_class v;

	uint8_t input[1024];
	uint8_t h[64];

	strcpy_s((char *)input, 1024, S);
	strcpy_s((char *)input + strlen(S), 1024 - 80, U);
	strcpy_s((char *)input + strlen(S) + strlen(U), 1024 - 160, password);
	CryptoNaClHash(h, input, strlen(S) + strlen(U) + strlen(password));
	mpz_import(x.get_mpz_t(), strlen(S) + strlen(U) + strlen(password), 1, 1, 0, 0, h);
	// x %= mpz_class(p);	// the value of the 512 bit hash result is clearly less than p
	mpz_powm_sec(v.get_mpz_t(), g, x.get_mpz_t(), p);

	mpz_class a, b;
	// prepare the random generator
	gmp_randstate_t randomState;
	gmp_randinit_default(randomState);
	gmp_randseed_ui(randomState, (unsigned long)time(NULL));

	mpz_urandomb(a.get_mpz_t(), randomState, BITS_COUNT);
	mpz_urandomb(b.get_mpz_t(), randomState, BITS_COUNT);

	//	A = g^a			->	B = 3v + g^b	// RESTful: A together with I
	mpz_class A, B, u;
	mpz_class S1;	// S of server
	mpz_class S_c;	// S of client

	mpz_powm_sec(A.get_mpz_t(), g, a.get_mpz_t(), p);
	mpz_powm_sec(B.get_mpz_t(), g, b.get_mpz_t(), p);
	B += 3*v;

	size_t n, m;
	mpz_export(input, &n, 1, 1, 0, 0, A.get_mpz_t());
	mpz_export(input + n, &m, 1, 1, 0, 0, B.get_mpz_t());
	CryptoNaClHash(h, input, n + m);
	mpz_import(u.get_mpz_t(), n + m, 1, 1, 0, 0, input);

	// u = H(A, B)		<-(B)
	// S = (B - 3g^x)^(a + ux)		// (g^b)^(a+ux) = g^b^a * g^b^(ux) = g^a * g^(ux))^b = (g^a*(g^x)^u)^b
	mpz_class tmp = a + u * x;
	mpz_powm_sec(t, g, x.get_mpz_t(), p);
	S_c = B - 3 * mpz_class(t);
	mpz_powm_sec(t, S_c.get_mpz_t(), tmp.get_mpz_t(), p);
	S_c = mpz_class(t);
	//
	//	M1 = H(A, B, S)	-> (if M1 was lost, no need to calculate u, S and verify M1)
	//					u = H(A, B)
	//					S = (Av^u)^b
	mpz_powm_sec(S1.get_mpz_t(), v.get_mpz_t(), u.get_mpz_t(), p);
	mpz_mul(t, A.get_mpz_t(), S1.get_mpz_t());
	mpz_powm_sec(S1.get_mpz_t(), t, b.get_mpz_t(), p);

	assert(S_c == S1);	// if they are equal, M1, M2 would certainly be equal
	//					verify M1
	//	verify M2		<-	M2 = H(A, M1, S)
	//	K = H(S)			K = H(S)

	mpz_clears(p, g, t, NULL);
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
	////UnitTestCongestControl();
	FlowTestAcknowledge();
	FlowTestRetransmission();
	UnitTestCRC();
	UnitTestICC();

	TrySRP6();
	UnitTestTweetNacl();
	//
	return 0;
}
