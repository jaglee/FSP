
#include "stdafx.h"


static const ControlBlock::seq_t FIRST_SN = 12;
static const int MAX_GAPS_NUM = 2;
static const int MAX_BLOCK_NUM = 16;
//static const int MAX_BLOCK_NUM = 0x10000;



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

	pSCB->SetSendWindow(FIRST_SN);
	ControlBlock::PFSP_SocketBuf skb = pSCB->GetSendBuf();
	//Assert::IsNotNull(skb);
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
	pSCB->sendWindowLimitSN = FIRST_SN + MAX_BLOCK_NUM;	// don't let size of send window limit the test
	assert(pSCB->sendWindowNextSN == FIRST_SN + 3);

	// acknowledge the first two
	r = socket.RespondToSNACK(FIRST_SN + 2, NULL, 0);
	assert(r == 2 && pSCB->sendWindowFirstSN == FIRST_SN + 2);
	assert(pSCB->CountSentInFlight() >= 0);

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
	assert(pSCB->CountSentInFlight() >= 0);

	// this is a legal but one gap is redundant, one is additional
	gaps[0].dataLength = htobe32(1);
	gaps[0].gapWidth = htobe32(1);
	gaps[1].dataLength = htobe32(1);
	gaps[1].gapWidth = htobe32(1);
	r = socket.RespondToSNACK(FIRST_SN + 3, gaps, 2);
	assert(r == 1 && pSCB->sendWindowFirstSN == FIRST_SN + 3);
	assert(pSCB->CountSentInFlight() >= 0);

	// two gaps, overlap with previous one [only to urge retransmission of those negatively acknowledged]
	gaps[0].dataLength = htobe32(1);
	gaps[0].gapWidth = htobe32(1);
	gaps[1].dataLength = htobe32(1);
	gaps[1].gapWidth = htobe32(1);
	r = socket.RespondToSNACK(FIRST_SN + 3, gaps, 2);
	assert(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 3);
	assert(pSCB->CountSentInFlight() >= 0);

	// two gaps, do real new acknowledgement: the 4th (the 5th has been acknowledged) and the 7th
	gaps[0].dataLength = htobe32(1);
	gaps[0].gapWidth = htobe32(1);
	gaps[1].dataLength = htobe32(1);
	gaps[1].gapWidth = htobe32(1);
	r = socket.RespondToSNACK(FIRST_SN + 5, gaps, 2);
	assert(r == 2 && pSCB->sendWindowFirstSN == FIRST_SN + 5);
	assert(pSCB->CountSentInFlight() >= 0);

	static const int MAX_BLOCK_NUM_L = 0x20000;	// 65536 * 2
	// a very large continuous data segment is acknowledged
	gaps[0].dataLength = htobe32(1);
	gaps[0].gapWidth = htobe32(1);
	gaps[1].dataLength = htobe32(1);
	gaps[1].gapWidth = htobe32(1);
	r = socket.RespondToSNACK(FIRST_SN + 0x1000A, gaps, 2);	
	//^ but the expectedSN is impossible for the small sending window!
	printf_s("RespondToSNACK(FIRST_SN + 0x1000A, gaps, 2):\n"
		"\tnAck = %d, CountSentInFlight() = %d\n"
		"\tsendWindowHeadPos = %d, sendWindowFirstSN = %u, sendWindowLimitSN = %u\n"
		, r, pSCB->CountSentInFlight()
		, pSCB->sendWindowHeadPos, pSCB->sendWindowFirstSN, pSCB->sendWindowLimitSN);

	// Test round-robin...
	for(int i = MAX_BLOCK_NUM_L + 2; i < MAX_BLOCK_NUM_L + 0x10000; i++)
	{
		skb = pSCB->GetSendBuf();
		if(skb == NULL)
			break;
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
	printf_s("RespondToSNACK(FIRST_SN + MAX_BLOCK_NUM_L + 0xF000, gaps, 2):\n"
		"\tnAck = %d, CountSentInFlight() = %d\n"
		"\tsendWindowHeadPos = %d, sendWindowFirstSN = %u, sendWindowLimitSN = %u\n"
		, r, pSCB->CountSentInFlight()
		, pSCB->sendWindowHeadPos, pSCB->sendWindowFirstSN, pSCB->sendWindowLimitSN);
}



void PrepareFlowTestResend(CSocketItemExDbg & dbgSocket, PControlBlock & pSCB)
{
	// set the begin of the send sequence number for the test to work properly
	// set the negotiated receive window parameter
	int memsize = sizeof(ControlBlock) + (sizeof ControlBlock::FSP_SocketBuf + MAX_BLOCK_SIZE) * 8;
	int32_t s1 = (memsize - sizeof(ControlBlock)) / 2;
	int32_t s2 = (memsize - sizeof(ControlBlock)) / 2;

	memset(& dbgSocket, 0, sizeof(CSocketItemExDbg));
	dbgSocket.dwMemorySize = memsize;
	if(dbgSocket.pControlBlock != NULL)
		free(dbgSocket.pControlBlock);
	pSCB = (ControlBlock *)malloc(dbgSocket.dwMemorySize);
	dbgSocket.pControlBlock = pSCB;

	pSCB->Init(s1, s2);
	pSCB->recvWindowFirstSN = pSCB->recvWindowNextSN = FIRST_SN;

	pSCB->SetSendWindow(FIRST_SN);
	ControlBlock::PFSP_SocketBuf skb = pSCB->GetSendBuf();
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
 * GetSendBuf
 * AllocRecvBuf
 * GetSelectiveNACK
 * RespondToSNACK
 */
void FlowTestRetransmission()
{
	CSocketItemExDbg dbgSocket;
	PControlBlock pSCB;
	
	PrepareFlowTestResend(dbgSocket, pSCB);	// dbgSocket.tRoundTrip_us == 0;
	dbgSocket.DoResend();

	struct
	{
		PktBufferBlock	pktBuffer;
		int32_t			n;
	} placeholder;
	//
	struct _KEEP_ALIVE
	{
		FSP_NormalPacketHeader hdr;
		FSP_PreparedKEEP_ALIVE ext;
	} *p = (_KEEP_ALIVE *)& placeholder.pktBuffer.hdr;
	//
	ControlBlock::seq_t seq4;

	memset(& placeholder, 0, sizeof(placeholder));
	int32_t len = dbgSocket.GenerateSNACK(p->ext, seq4, sizeof(FSP_NormalPacketHeader));

	p->hdr.hs.opCode = KEEP_ALIVE;
	p->hdr.hs.major = THIS_FSP_VERSION;
	p->hdr.hs.hsp = htobe16(uint16_t(len));

	// Both KEEP_ALIVE and ACK_FLUSH are payloadless out-of-band control block which always apply current session key
	// See also ControlBlock::SetSequenceFlags
	p->hdr.sequenceNo = htobe32(pSCB->sendWindowNextSN - 1);
	p->hdr.expectedSN = htobe32(seq4);
	p->hdr.ClearFlags();
	p->hdr.SetRecvWS(pSCB->AdRecvWS(seq4));

	dbgSocket.SetIntegrityCheckCode(& p->hdr, NULL, 0, p->ext.GetSaltValue());

	// Firstly emulate receive the packet before emulate OnGetKeepAlive
	dbgSocket.headPacket = & placeholder.pktBuffer;
	dbgSocket.headPacket->pktSeqNo = FIRST_SN + 3;
	dbgSocket.headPacket->lenData = 0;
	dbgSocket.tRoundTrip_us = 1;
	dbgSocket.tRecentSend = NowUTC() + 1;
	// See also CSocketItemEx::OnGetKeepAlive
	FSP_SelectiveNACK::GapDescriptor *snack;
	int n;
	ControlBlock::seq_t seq5;
	dbgSocket.ValidateSNACK(seq5, snack, n);

	assert(seq5 == seq4 && n == 1);

	dbgSocket.RespondToSNACK(seq5, snack, n);

	dbgSocket.DoResend();

	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadSend();
	assert(skb->flags == 0);	// GetFlag<IS_ACKNOWLEDGED>()
	assert((skb + 1)->flags == 0);	// GetFlag<IS_ACKNOWLEDGED>()
	assert((skb + 3)->GetFlag<IS_ACKNOWLEDGED>());
	assert(dbgSocket.GetControlBlock()->sendWindowFirstSN == FIRST_SN + 2);

	//
	// Round robin. Firstly, emulate further send.
	//
	skb = pSCB->GetSendBuf();
	assert(skb != NULL);
	skb->SetFlag<IS_COMPLETED>();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 5);

	skb = pSCB->GetSendBuf();
	assert(skb != NULL);
	skb->SetFlag<IS_COMPLETED>();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 6);

	// the receive window is slided
	pSCB->SlideRecvWindowByOne();
	pSCB->SlideRecvWindowByOne();

	// further receiving
	skb = pSCB->AllocRecvBuf(FIRST_SN + 4);
	assert(skb != NULL);
	skb->SetFlag<IS_FULFILLED>();

	skb = pSCB->AllocRecvBuf(FIRST_SN + 5);
	assert(skb != NULL);
	skb->SetFlag<IS_FULFILLED>();

	skb = pSCB->AllocRecvBuf(FIRST_SN + 6);
	assert(skb == NULL);

	len = dbgSocket.GenerateSNACK(p->ext, seq4, sizeof(FSP_NormalPacketHeader));
	p->hdr.hs.hsp = htobe16(uint16_t(len));

	p->hdr.sequenceNo = htobe32(pSCB->sendWindowNextSN - 1);
	p->hdr.expectedSN = htobe32(seq4);
	p->hdr.ClearFlags();
	p->hdr.SetRecvWS(pSCB->AdRecvWS(seq4));

	dbgSocket.SetIntegrityCheckCode(&p->hdr, NULL, 0, p->ext.GetSaltValue());
	// as it is an out-of-band packet, assume pre-set values are kept
	dbgSocket.tRecentSend = NowUTC() + 3;
	dbgSocket.ValidateSNACK(seq5, snack, n);

	assert(seq5 == seq4 && n == 1);

	dbgSocket.RespondToSNACK(seq5, snack, n);
	dbgSocket.DoResend();

	// TODO: Test calculation of RTT and Keep alive timeout 
}


//
void FlowTestRecvWinRoundRobin()
{
	CSocketItemExDbg dbgSocket;
	PControlBlock pSCB;

	// The send buffer space is fulfilled, while the third receive buffer block is free
	PrepareFlowTestResend(dbgSocket, pSCB);

	int32_t m;
	void * buf = pSCB->InquireSendBuf(& m);
	// should be NULL, -ENOMEM
	printf_s("InquireSendBuf: buf = %p, size = %d\n", buf, m);

	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadRecv();
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;

	// FIRST_SN + 1
	skb++;
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;

	// FIRST_SN + 3;
	skb++;
	skb++;
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;

	// but eot? don't care it yet.
	bool eot;
	buf = pSCB->InquireRecvBuf(m, eot);
	printf_s("Should return the first two blocks:\n"
		"InquireRecvBuf#1, buf = %p, size = %d, eot = %d\n", buf, m, eot);

	if (m > 0)
		pSCB->MarkReceivedFree(m);

	skb = pSCB->AllocRecvBuf(FIRST_SN + 2);	// used to be free
	assert(skb != NULL);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->SetFlag<IS_FULFILLED>();

	// Round-robin allocation
	skb = pSCB->AllocRecvBuf(FIRST_SN + 4);
	assert(skb != NULL);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->SetFlag<IS_FULFILLED>();

	skb = pSCB->AllocRecvBuf(FIRST_SN + 5);
	assert(skb != NULL);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->SetFlag<IS_FULFILLED>();

	buf = pSCB->InquireRecvBuf(m, eot);
	printf_s("Should return the last two blocks:\n"
		"InquireRecvBuf#3, buf = %p, size = %d, eot = %d\n", buf, m, eot);

	if (m > 0)
		pSCB->MarkReceivedFree(m);

	skb = pSCB->AllocRecvBuf(FIRST_SN + 6);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->SetFlag<IS_FULFILLED>();

	skb = pSCB->AllocRecvBuf(FIRST_SN + 7);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->SetFlag<IS_FULFILLED>();

	skb = pSCB->AllocRecvBuf(FIRST_SN + 8);
	assert(skb == NULL);

	buf = pSCB->InquireRecvBuf(m, eot);
	printf_s("Should round-robin to the start, return the whole buffer space:\n"
		"InquireRecvBuf, #4, buf = %p, size = %d, eot = %d\n", buf, m, eot);

	if (m > 0)
		pSCB->MarkReceivedFree(m);
	//TODO: more test, now EOT should be taken into care of
}
