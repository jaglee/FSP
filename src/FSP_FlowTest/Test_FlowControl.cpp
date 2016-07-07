
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
	assert(pSCB->CountSentInFlight() >= 0);
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
		"\tsendWindowHeadPos, sendWindowFirstSN = %u, sendWindowSize = %d\n"
		, r, pSCB->CountSentInFlight()
		, pSCB->sendWindowHeadPos, pSCB->sendWindowFirstSN, pSCB->sendWindowSize);

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
		"\tsendWindowHeadPos, sendWindowFirstSN = %u, sendWindowSize = %d\n"
		, r, pSCB->CountSentInFlight()
		, pSCB->sendWindowHeadPos, pSCB->sendWindowFirstSN, pSCB->sendWindowSize);
}



void PrepareFlowTestResend(CSocketItemExDbg & dbgSocket, PControlBlock & pSCB)
{
	// set the begin of the send sequence number for the test to work properly
	// set the negotiated receive window parameter
	int memsize = sizeof(ControlBlock) + (sizeof ControlBlock::FSP_SocketBuf + MAX_BLOCK_SIZE) * 8;
	memset(& dbgSocket, 0, sizeof(CSocketItemExDbg));
	dbgSocket.dwMemorySize = memsize;
	if(dbgSocket.pControlBlock != NULL)
		free(dbgSocket.pControlBlock);
	pSCB = (ControlBlock *)malloc(dbgSocket.dwMemorySize);
	dbgSocket.pControlBlock = pSCB;
	pSCB->Init((memsize - sizeof(ControlBlock)) / 2, (memsize - sizeof(ControlBlock)) / 2);
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

	// UNRESOLVED! I don't know why it report 'Stack around pktBuffer was corrupted'
	// what is the content of the selective negative acknowledgement?
	// See also CSocketItemEx::SendSNACK
	//static int32_t guardian1 = 0xAAAAAAAA;
	//static PktBufferBlock pktBuffer;
	//static int32_t guardian2 = 0xAAAAAAAA;
	PktBufferBlock pktBuffer;
	memset(& pktBuffer, 0, sizeof(pktBuffer));
	struct _KEEP_ALIVE
	{
		FSP_NormalPacketHeader hdr;
		FSP_PreparedKEEP_ALIVE ext;
	} *p = (_KEEP_ALIVE *) & pktBuffer.hdr;
	ControlBlock::seq_t seq4;
	////No, GetSelectiveNACK does not corrupt the memory
	//int n = dbgSocket.pControlBlock->GetSelectiveNACK(seq4, p->ext.gaps, sizeof(p->ext.gaps) / sizeof(p->ext.gaps[0]));
	int32_t len = dbgSocket.GenerateSNACK(p->ext, seq4, sizeof(FSP_NormalPacketHeader));

	p->hdr.hs.version = THIS_FSP_VERSION;
	p->hdr.hs.opCode = KEEP_ALIVE;
	p->hdr.hs.hsp = htobe16(uint16_t(len));

	// Both KEEP_ALIVE and ACK_FLUSH are payloadless out-of-band control block which always apply current session key
	// See also ControlBlock::SetSequenceFlags
	p->hdr.sequenceNo = htobe32(pSCB->sendWindowNextSN - 1);
	p->hdr.expectedSN = htobe32(seq4);
	p->hdr.ClearFlags();
	p->hdr.SetRecvWS(pSCB->RecvWindowSize());
	
	dbgSocket.SetIntegrityCheckCode(& p->hdr, NULL, 0, p->ext.GetSaltValue());

	// Firstly emulate receive the packet before emulate OnGetKeepAlive
	dbgSocket.headPacket = & pktBuffer;
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

	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadSend();
	assert(skb->flags == 0);	// GetFlag<IS_ACKNOWLEDGED>()
	assert((skb + 1)->flags == 0);	// GetFlag<IS_ACKNOWLEDGED>()
	assert((skb + 3)->GetFlag<IS_ACKNOWLEDGED>());
	assert(dbgSocket.GetControlBlock()->sendWindowFirstSN == FIRST_SN + 2);

	// TODO: Test round-robin, by slide one...
	// TODO: Test calculation of RTT and Keep alive timeout 
}
