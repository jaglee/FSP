
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

	pSCB->sendBufferNextSN = pSCB->sendWindowNextSN = FIRST_SN + 1;
	pSCB->sendWindowFirstSN = FIRST_SN;
	pSCB->sendWindowLimitSN = FIRST_SN + MAX_BLOCK_NUM;
	// Pretend that the first packet has been sent and is waiting acknowledgement...
	int r = socket.AcceptSNACK(FIRST_SN + 1, NULL, 0);
	assert(r == 1 && pSCB->sendBufferNextSN == pSCB->sendWindowFirstSN);
	assert(pSCB->sendWindowFirstSN == FIRST_SN + 1);
	assert(pSCB->sendWindowNextSN == FIRST_SN + 1);

	pSCB->SetSendWindow(FIRST_SN);
	pSCB->sendWindowLimitSN = FIRST_SN + MAX_BLOCK_NUM;	// don't let size of send window limit the test
	ControlBlock::PFSP_SocketBuf skb = pSCB->GetSendBuf();
	//Assert::IsNotNull(skb);
	assert(pSCB->sendBufferNextSN == FIRST_SN + 1);
	skb->ReInitMarkComplete();

	skb = pSCB->GetSendBuf();
	skb->ReInitMarkComplete();
	pSCB->GetSendBuf();
	skb->ReInitMarkComplete();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 3);

	// A NULL acknowledgement, Keep-Alive
	r = socket.AcceptSNACK(FIRST_SN, NULL, 0);
	assert(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN);

	// emulate sending, assume 3 packets sent
	pSCB->sendWindowNextSN += 3;
	assert(pSCB->sendWindowNextSN == FIRST_SN + 3);

	// acknowledge the first two
	r = socket.AcceptSNACK(FIRST_SN + 2, NULL, 0);
	assert(r == 2 && pSCB->sendWindowFirstSN == FIRST_SN + 2);
	assert(pSCB->CountSentInFlight() >= 0);

	// Now, more test...
	for(int i = 3; i < MAX_BLOCK_NUM; i++)
	{
		skb = pSCB->GetSendBuf();
		assert(skb != NULL);
		skb->ReInitMarkComplete();
	}
	pSCB->sendWindowNextSN += MAX_BLOCK_NUM - 3;
	assert(pSCB->sendWindowNextSN == FIRST_SN + MAX_BLOCK_NUM);

	// All buffer blocks should have been consumed after the two acknowledged have been allocated
	// [however, sendWindowSize is not reduced yet]
	skb = pSCB->GetSendBuf();	// the two acknowledged
	skb->ReInitMarkComplete();
	skb = pSCB->GetSendBuf();
	skb->ReInitMarkComplete();
	skb = pSCB->GetSendBuf();	// no space in the send buffer.
	assert(skb == NULL);

	// assume the third is a gap...
	gaps[0].dataLength = htole32(1);
	gaps[0].gapWidth = htole32(1);
	//// this is an illegal one	// now it is perfectly OK
	//r = socket.AcceptSNACK(FIRST_SN, gaps, 1);
	//assert(r == -EBADF && pSCB->sendWindowFirstSN == FIRST_SN + 2);
	//assert(pSCB->CountUnacknowledged() >= 0);
	//// again, an outdated one
	//r = socket.AcceptSNACK(FIRST_SN + 2, gaps, 1);
	//assert(r == -EDOM && pSCB->sendWindowFirstSN == FIRST_SN + 2);
	//assert(pSCB->CountUnacknowledged() >= 0);

	// this is a legal one: the first two has been acknowledged; the 3rd and the 5th is to be acknowledged
	r = socket.AcceptSNACK(FIRST_SN + 3, gaps, 1);
	assert(r == 1 && pSCB->sendWindowFirstSN == FIRST_SN + 3);	// used to be r == 2
	assert(pSCB->CountSentInFlight() >= 0);

	// this is a legal but one gap is redundant, one is additional
	gaps[0].dataLength = htole32(1);
	gaps[0].gapWidth = htole32(1);
	gaps[1].dataLength = htole32(1);
	gaps[1].gapWidth = htole32(1);
	r = socket.AcceptSNACK(FIRST_SN + 3, gaps, 2);
	assert(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 3);	// used to be r == 1
	assert(pSCB->CountSentInFlight() >= 0);

	// two gaps, overlap with previous one [only to urge retransmission of those negatively acknowledged]
	gaps[0].dataLength = htole32(1);
	gaps[0].gapWidth = htole32(1);
	gaps[1].dataLength = htole32(1);
	gaps[1].gapWidth = htole32(1);
	r = socket.AcceptSNACK(FIRST_SN + 3, gaps, 2);
	assert(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 3);
	assert(pSCB->CountSentInFlight() >= 0);

	// two gaps, do real new acknowledgement: the 4th (the 5th has been acknowledged) and the 7th
	gaps[0].dataLength = htole32(1);
	gaps[0].gapWidth = htole32(1);
	gaps[1].dataLength = htole32(1);
	gaps[1].gapWidth = htole32(1);
	r = socket.AcceptSNACK(FIRST_SN + 5, gaps, 2);
	assert(r == 2 && pSCB->sendWindowFirstSN == FIRST_SN + 5);
	assert(pSCB->CountSentInFlight() >= 0);

	static const int MAX_BLOCK_NUM_L = 0x20000;	// 65536 * 2
	// a very large continuous data segment is acknowledged
	gaps[0].dataLength = htole32(1);
	gaps[0].gapWidth = htole32(1);
	gaps[1].dataLength = htole32(1);
	gaps[1].gapWidth = htole32(1);
	r = socket.AcceptSNACK(FIRST_SN + 0x1000A, gaps, 2);	
	//^ but the expectedSN is impossible for the small sending window!
	printf_s("AcceptSNACK(FIRST_SN + 0x1000A, gaps, 2):\n"
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
		skb->ReInitMarkComplete();
	}
	pSCB->sendWindowNextSN += 0x10000;	// queuing to send is not the same as sending
	pSCB->sendWindowLimitSN = pSCB->sendWindowNextSN + MAX_BLOCK_NUM;

	// an even larger continuous data segment is acknowledged
	gaps[0].dataLength = htole32(1);
	gaps[0].gapWidth = htole32(1);
	gaps[1].dataLength = htole32(1);
	gaps[1].gapWidth = htole32(1);
	r = socket.AcceptSNACK(FIRST_SN + MAX_BLOCK_NUM_L + 0xF000, gaps, 2);
	printf_s("AcceptSNACK(FIRST_SN + MAX_BLOCK_NUM_L + 0xF000, gaps, 2):\n"
		"\tnAck = %d, CountSentInFlight() = %d\n"
		"\tsendWindowHeadPos = %d, sendWindowFirstSN = %u, sendWindowLimitSN = %u\n"
		, r, pSCB->CountSentInFlight()
		, pSCB->sendWindowHeadPos, pSCB->sendWindowFirstSN, pSCB->sendWindowLimitSN);
}



void PrepareFlowTestResend(CSocketItemExDbg& dbgSocket, PControlBlock& pSCB)
{
	static SProcessRoot r;

	// set the begin of the send sequence number for the test to work properly
	// set the negotiated receive window parameter
	int memsize = sizeof(ControlBlock) + (sizeof ControlBlock::FSP_SocketBuf + MAX_BLOCK_SIZE) * 8;
	int32_t s1 = (memsize - sizeof(ControlBlock)) / 2;
	int32_t s2 = (memsize - sizeof(ControlBlock)) / 2;

	memset(&dbgSocket, 0, sizeof(CSocketItemExDbg));
	dbgSocket.dwMemorySize = memsize;
	if (dbgSocket.pControlBlock != NULL)
		free(dbgSocket.pControlBlock);
	pSCB = (ControlBlock*)malloc(dbgSocket.dwMemorySize);
	dbgSocket.pControlBlock = pSCB;

	pSCB->Init(s1, s2);
	pSCB->SetRecvWindow(FIRST_SN);
	pSCB->SetSendWindow(FIRST_SN);

	ControlBlock::PFSP_SocketBuf skb = pSCB->GetSendBuf();
	skb->ReInitMarkComplete();
	skb->timeSent = NowUTC();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 1);

	skb = pSCB->GetSendBuf();
	skb->ReInitMarkComplete();
	skb->timeSent = NowUTC();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 2);

	skb = pSCB->GetSendBuf();
	skb->ReInitMarkComplete();
	skb->timeSent = NowUTC();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 3);

	skb = pSCB->GetSendBuf();
	skb->ReInitMarkComplete();
	skb->timeSent = NowUTC();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 4);

	skb = pSCB->GetSendBuf();
	assert(skb == NULL);	// as we knew there are only 4 packet slots 

	++(pSCB->sendWindowNextSN);

	++(pSCB->sendWindowNextSN);

	++(pSCB->sendWindowNextSN);

	++(pSCB->sendWindowNextSN);

	ControlBlock::PFSP_SocketBuf skb5 = pSCB->AllocRecvBuf(FIRST_SN);
	assert(skb5 != NULL);

	skb5->ReInitMarkComplete();
	skb5->timeRecv = NowUTC();

	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 1);
	assert(skb5 != NULL);
	assert(pSCB->recvWindowNextSN == FIRST_SN + 2);

	skb5->ReInitMarkComplete();
	skb5->timeRecv = NowUTC();

	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 3);
	assert(skb5 != NULL);
	assert(pSCB->recvWindowNextSN == FIRST_SN + 4);

	skb5->ReInitMarkComplete();
	skb5->timeRecv = NowUTC();

	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 4);
	assert(skb5 == NULL);	// No more space in the receive buffer

	pSCB->state = ESTABLISHED;
	dbgSocket.AddKinshipTo(&r);
}



/**
 * GetSendBuf
 * AllocRecvBuf
 * GetSelectiveNACK
 * AcceptSNACK
 */
void FlowTestRetransmission()
{
	CSocketItemExDbg dbgSocket;
	PControlBlock pSCB;
	
	PrepareFlowTestResend(dbgSocket, pSCB);	// dbgSocket.tRoundTrip_us == 0;
	dbgSocket.DoEventLoop();

	struct
	{
		PktBufferBlock	pktBuffer;
		int32_t			n;
	} placeholder;
	//
	FSP_KeepAlivePacket *p = (FSP_KeepAlivePacket *)&placeholder.pktBuffer.hdr;

	memset(& placeholder, 0, sizeof(placeholder));

	int32_t len = dbgSocket.GenerateSNACK(*p);

	dbgSocket.SignHeaderWith((FSP_FixedHeader *)&p->hdr, KEEP_ALIVE, uint16_t(len), pSCB->sendWindowNextSN - 1, ++dbgSocket.nextOOBSN);
	dbgSocket.SetIntegrityCheckCode(&p->hdr, &p->mp, len - sizeof(p->hdr), dbgSocket.GetSalt(p->hdr));

	// Firstly emulate receive the packet before emulate OnGetKeepAlive
	dbgSocket.headPacket = & placeholder.pktBuffer;
	dbgSocket.pktSeqNo = FIRST_SN + 3;
	dbgSocket.lenPktData = 0;
	dbgSocket.tRoundTrip_us = 1;
	dbgSocket.tRecentSend = NowUTC() + 1;
	// See also CSocketItemEx::OnGetKeepAlive
	FSP_SelectiveNACK *snack = &p->sentinel;

	// there used to be seq4 to record the expected sequence number
	ControlBlock::seq_t seq5;
	int n = dbgSocket.ValidateSNACK(seq5, snack);
	assert(seq5 == FIRST_SN + 2 && n == 1);

	dbgSocket.AcceptSNACK(seq5, p->gaps, n);
	dbgSocket.DoEventLoop();

	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadSend();
	assert(skb->flags == 0);
	assert((skb + 1)->flags == 0);
	assert((skb + 3)->marks & ControlBlock::FSP_BUF_ACKED);
	assert(dbgSocket.GetControlBlock()->sendWindowFirstSN == FIRST_SN + 2);

	//
	// Round robin. Firstly, emulate further send.
	//
	skb = pSCB->GetSendBuf();
	assert(skb != NULL);
	skb->ReInitMarkComplete();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 5);

	skb = pSCB->GetSendBuf();
	assert(skb != NULL);
	skb->ReInitMarkComplete();
	assert(pSCB->sendBufferNextSN == FIRST_SN + 6);

	// the receive window is slided
	pSCB->SlideRecvWindowByOne();
	pSCB->SlideRecvWindowByOne();

	// further receiving
	skb = pSCB->AllocRecvBuf(FIRST_SN + 4);
	assert(skb != NULL);
	skb->ReInitMarkComplete();

	skb = pSCB->AllocRecvBuf(FIRST_SN + 5);
	assert(skb != NULL);
	skb->ReInitMarkComplete();

	skb = pSCB->AllocRecvBuf(FIRST_SN + 6);
	assert(skb == NULL);
	//skb->ReInitMarkComplete();

	len = dbgSocket.GenerateSNACK(*p);

	dbgSocket.SignHeaderWith((FSP_FixedHeader *)&p->hdr, KEEP_ALIVE, uint16_t(len), pSCB->sendWindowNextSN - 1, ++dbgSocket.nextOOBSN);
	dbgSocket.SetIntegrityCheckCode(&p->hdr, &p->mp, len - sizeof(p->hdr), dbgSocket.GetSalt(p->hdr));
	// as it is an out-of-band packet, assume preset values are kept
	dbgSocket.tRecentSend = NowUTC() + 3;

	n = dbgSocket.ValidateSNACK(seq5, snack);
	assert(seq5 == FIRST_SN + 2 && n == 1);

	dbgSocket.AcceptSNACK(seq5, p->gaps, n);
	dbgSocket.DoEventLoop();

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
	// should be NULL, 0
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
	int32_t nB;
	bool eot;
	buf = pSCB->InquireRecvBuf(m, nB, eot);
	printf_s("Should return the first two blocks:\n"
		"InquireRecvBuf#1, buf = %p, size = %d, eot = %d\n", buf, m, eot);
	pSCB->MarkReceivedFree(nB);

	skb = pSCB->AllocRecvBuf(FIRST_SN + 2);	// used to be free
	assert(skb != NULL);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->ReInitMarkComplete();

	// Round-robin allocation
	skb = pSCB->AllocRecvBuf(FIRST_SN + 4);
	assert(skb != NULL);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->ReInitMarkComplete();

	skb = pSCB->AllocRecvBuf(FIRST_SN + 5);
	assert(skb != NULL);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->ReInitMarkComplete();

	buf = pSCB->InquireRecvBuf(m, nB, eot);
	printf_s("Should return the last two blocks:\n"
		"InquireRecvBuf#3, buf = %p, size = %d, eot = %d\n", buf, m, eot);
	pSCB->MarkReceivedFree(nB);

	skb = pSCB->AllocRecvBuf(FIRST_SN + 6);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->ReInitMarkComplete();

	skb = pSCB->AllocRecvBuf(FIRST_SN + 7);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->ReInitMarkComplete();

	skb = pSCB->AllocRecvBuf(FIRST_SN + 8);
	assert(skb == NULL);

	buf = pSCB->InquireRecvBuf(m, nB, eot);
	printf_s("Should round-robin to the start, return the whole buffer space:\n"
		"InquireRecvBuf - buf = %p, size = %d, eot = %d\n", buf, m, eot);
	pSCB->MarkReceivedFree(nB);

	skb = pSCB->AllocRecvBuf(FIRST_SN + 8);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE - 2;
	skb->SetFlag<TransactionEnded>();
	skb->ReInitMarkComplete();

	skb = pSCB->AllocRecvBuf(FIRST_SN + 9);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->ReInitMarkComplete();

	skb = pSCB->AllocRecvBuf(FIRST_SN + 10);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->ReInitMarkComplete();

	buf = pSCB->InquireRecvBuf(m, nB, eot);
	printf_s("Should return the first block, with eot flag set:\n"
		"InquireRecvBuf - buf = %p, size = %d, eot = %d\n", buf, m, eot);
	pSCB->MarkReceivedFree(nB);

	skb = pSCB->AllocRecvBuf(FIRST_SN + 11);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->ReInitMarkComplete();

	// This block round-robin
	skb = pSCB->AllocRecvBuf(FIRST_SN + 12);
	assert(skb != NULL);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->ReInitMarkComplete();

	buf = pSCB->InquireRecvBuf(m, nB, eot);
	printf_s("Should return the 2nd, 3rd and 4th blocks:\n"
		"InquireRecvBuf - buf = %p, size = %d, eot = %d\n", buf, m, eot);
	pSCB->MarkReceivedFree(nB);

	buf = pSCB->InquireRecvBuf(m, nB, eot);
	printf_s("Should round-robin to the 1st block again:\n"
		"InquireRecvBuf - buf = %p, size = %d, eot = %d\n", buf, m, eot);
	pSCB->MarkReceivedFree(nB);

	// Rare but possible case of a fulfilled payload with a payload-less EoT
	skb = pSCB->AllocRecvBuf(FIRST_SN + 13);
	assert(skb != NULL);
	skb->opCode = PURE_DATA;
	skb->len = MAX_BLOCK_SIZE;
	skb->ReInitMarkComplete();

	skb = pSCB->AllocRecvBuf(FIRST_SN + 14);
	assert(skb != NULL);
	skb->opCode = PURE_DATA;
	skb->len = 0;
	skb->SetFlag<TransactionEnded>();
	skb->ReInitMarkComplete();

	buf = pSCB->InquireRecvBuf(m, nB, eot);
	printf_s("Should round-robin to the 2nd and 3rd blocks:\n"
		"InquireRecvBuf - buf = %p, size = %d, eot = %d\n", buf, m, eot);
	pSCB->MarkReceivedFree(nB);
}
