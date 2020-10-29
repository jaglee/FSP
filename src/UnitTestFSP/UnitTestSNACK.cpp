#include "targetver.h"

#include "FSP_TestClass.h"

// Headers for CppUnitTest
#define _ALLOW_KEYWORD_MACROS
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


/**
 * Unit Test of:
 * InquireSendBuf
 * InquireRecvBuf
 * FetchReceived
 * AllocRecvBuf
 * GetSelectiveNACK
 */
void UnitTestSendRecvWnd()
{
	int memsize = sizeof(ControlBlock) + (sizeof ControlBlock::FSP_SocketBuf + MAX_BLOCK_SIZE) * 8;
	int32_t s1 = (memsize - sizeof(ControlBlock)) / 2;
	int32_t s2 = (memsize - sizeof(ControlBlock)) / 2;
	const ControlBlock::seq_t FIRST_SN = 12;

	ControlBlock *pSCB = (ControlBlock *)malloc(memsize);
	pSCB->Init(s1, s2);
	//pSCB->sendWindowSize = pSCB->sendBufferSize;	// shall do nothing with send buffer management
	//^ shall set to min(sendBufferSize, remoteReceiveWindowSize);

	// set the begin of the send sequence number for the test to work properly
	// set the negotiated receive window parameter
	pSCB->SetRecvWindow(FIRST_SN);
	pSCB->SetSendWindow(FIRST_SN);

	ControlBlock::PFSP_SocketBuf skb = pSCB->GetSendBuf();
	Assert::IsNotNull(skb);
	Assert::IsTrue(pSCB->sendBufferNextSN == FIRST_SN + 1);

	int32_t m;
	void *inplaceBuf = pSCB->InquireSendBuf(& m);
	Assert::IsNotNull(inplaceBuf);	// it might fail if memsize is too small
	Assert::IsTrue(m > 0);			// it might fail if memsize is too small
	if(m < MAX_BLOCK_SIZE * 2)
		return;

	ControlBlock::PFSP_SocketBuf skb3 = pSCB->HeadSend() + 2;
	skb->ReInitMarkAcked();
	skb3->ReInitMarkAcked();

	// emulate received the first data packet
	ControlBlock::PFSP_SocketBuf skb4 = pSCB->AllocRecvBuf(FIRST_SN);
	uint8_t *recvBuf;

	Assert::IsNotNull(skb4);
	recvBuf = pSCB->GetRecvPtr(skb4);

	Assert::IsTrue(pSCB->recvWindowFirstSN == FIRST_SN);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 1);
	// TODO: SCB buffer pointer to user space pointer
	skb4->opCode = PURE_DATA;
	skb4->len = MAX_BLOCK_SIZE - 13;
	skb4->SetFlag<TransactionEnded>();
	skb4->ReInitMarkComplete();

	int32_t m2;	// onReturn it should == skb4->len, i.e. MAX_BLOCK_SIZE - 13
	int32_t nB;	// number of blocks
	bool b;
	uint8_t *recvBuf2 = (uint8_t *)pSCB->InquireRecvBuf(m2, nB, b);
	Assert::IsTrue(recvBuf2 == recvBuf);
	Assert::IsTrue(m2 == MAX_BLOCK_SIZE - 13);
	pSCB->MarkReceivedFree(nB);
	Assert::IsTrue(pSCB->recvWindowFirstSN == FIRST_SN + 1);

	ControlBlock::PFSP_SocketBuf skb5 = pSCB->AllocRecvBuf(FIRST_SN);
	Assert::IsTrue(skb5 != skb4);	// out of order, and it depends that IsNull(skb5)
	//
	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 6);
	Assert::IsNull(skb5);			// no more advertisable receive window space

	// emulate a received message that crosses two packet
	// assume the packets are received out of the order
	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 2);
	Assert::IsNotNull(skb5);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 3);
	recvBuf2 = pSCB->GetRecvPtr(skb5);
	Assert::IsTrue(recvBuf2 - recvBuf == MAX_BLOCK_SIZE * 2);

	skb5->opCode = PURE_DATA;
	skb5->len = MAX_BLOCK_SIZE - 13;
	skb5->SetFlag<TransactionEnded>();
	skb5->ReInitMarkComplete();

	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 1);
	Assert::IsNotNull(skb5);
	//Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 2);

	skb5->opCode = PURE_DATA;
	skb5->len = MAX_BLOCK_SIZE;
	skb5->ClearFlags();
	skb5->ReInitMarkComplete();

	// emulate a received-ahead packet
	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 4);
	Assert::IsNotNull(skb5);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 5);
	recvBuf2 = pSCB->GetRecvPtr(skb5);
	Assert::IsTrue(recvBuf2 == recvBuf);	// because the size of the receive queue == MAX_BLOCK_SIZE * 4

	skb5->opCode = PURE_DATA;
	skb5->len = MAX_BLOCK_SIZE - 13;
	skb5->SetFlag<TransactionEnded>();
	skb5->ReInitMarkComplete();

	// what is the content of the selective negative acknowledgement?
	FSP_SelectiveNACK::GapDescriptor snack[4];
	ControlBlock::seq_t seq4;
	int m4 = pSCB->GetSelectiveNACK(seq4, snack, 4);
	// 0[delivered], 1, 2, x, 4 {, x, 6[but IS_FULFILLED is unset!]}
	Assert::IsTrue(m4 == 1 && seq4 == FIRST_SN + 3);
	Assert::IsTrue(snack[0].dataLength == 1 && snack[0].gapWidth == 1);

	BYTE * stBuf = (BYTE *)_alloca(memsize >> 2);
	memset(stBuf, 'S', memsize >> 2);

	// See CSocketItemDl::FetchReceived()
	// firstly, skip those already delivered
	ControlBlock::PFSP_SocketBuf p = pSCB->GetFirstReceived();
	while(p->opCode == 0)
	{
		pSCB->SlideRecvWindowByOne();
		p = pSCB->GetFirstReceived();
	}
	//
	while(p->IsComplete() && _InterlockedExchange8((char *)& p->opCode, 0) != 0)
	{
		pSCB->SlideRecvWindowByOne();
		p->ReInitMarkDelivered();
		if(p->GetFlag<TransactionEnded>())
			break;
		p = pSCB->GetFirstReceived();
	}
	Assert::IsTrue(pSCB->recvWindowFirstSN == FIRST_SN + 3);

	skb4 = pSCB->AllocRecvBuf(FIRST_SN + 6);
	Assert::IsNotNull(skb4);
	skb4->opCode = PURE_DATA;
	skb4->len = MAX_BLOCK_SIZE - 13;
	skb4->ReInitMarkComplete();

	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 7);

	m4 = pSCB->GetSelectiveNACK(seq4, snack, 4);
	// 0[delivered], 1[delivered], 2[delivered], x, 4{overlay 0}, x{overlay 1}, 6{[, 7 but IS_FULFILLED is unset!]}
	Assert::IsTrue(m4 == 2 && seq4 == FIRST_SN + 3
		&& snack[0].dataLength == 1 && snack[0].gapWidth == 1
		&& snack[1].dataLength == 1 && snack[1].gapWidth == 1);

	// Clean up
	free(pSCB);
}



/**
 * Unit test of various GenerateSNACK
 */
static const ControlBlock::seq_t FIRST_SN = 12;
static const int MAX_GAPS_NUM = 2;
static const int MAX_BLOCK_NUM = 0x20000;	// 65536 * 2
void UnitTestGenerateSNACK()
{
	CSocketItemExDbg socket(MAX_BLOCK_NUM, MAX_BLOCK_NUM);
	ControlBlock *pSCB = socket.GetControlBlock();
	pSCB->SetRecvWindow(FIRST_SN);

	FSP_SelectiveNACK::GapDescriptor gaps[MAX_GAPS_NUM];
	ControlBlock::seq_t seq0;

	// firstly, without a gap
	int r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 0 && seq0 == FIRST_SN);

	// secondly, one gap only
	ControlBlock::PFSP_SocketBuf skb1 = socket.AllocRecvBuf(FIRST_SN);
	Assert::IsNotNull(skb1);
	skb1->opCode = PERSIST;	// start of the transmit transaction
	skb1->len = 1;			// A PERSIST cannot be NULL
	skb1->SetFlag<TransactionEnded>();
	skb1->ReInitMarkComplete();
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 1);

	skb1 = socket.AllocRecvBuf(FIRST_SN + 2);
	Assert::IsTrue(pSCB->recvWindowExpectedSN == FIRST_SN + 1);
	Assert::IsNotNull(skb1);
	skb1->opCode = PURE_DATA;
	skb1->ReInitMarkComplete();
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 3);

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 1 && seq0 == FIRST_SN + 1 && gaps[0].gapWidth == 1 && gaps[0].dataLength == 1);

	// when a very large gap among small continuous data segments found
	skb1 = socket.AllocRecvBuf(FIRST_SN + 0x10003);
	Assert::IsNotNull(skb1);
	skb1->opCode = PURE_DATA;	// A PUER_DATA can be payloadless, however
	skb1->ReInitMarkComplete();
	Assert::IsTrue(pSCB->recvWindowExpectedSN == FIRST_SN + 1);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 0x10004);

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	// gap1: 1, data1: 2, gap2: 3~0x10002(inclusive), data2: 0x10003
	Assert::IsTrue(r == 2 && seq0 == FIRST_SN + 1
		&& gaps[0].gapWidth == 1 && gaps[0].dataLength == 1
		&& gaps[1].gapWidth == 0x10000 && gaps[1].dataLength == 1
	);

	skb1 = socket.AllocRecvBuf(FIRST_SN + 0x8003);
	Assert::IsNotNull(skb1);
	skb1->opCode = PURE_DATA;
	skb1->ReInitMarkComplete();
	Assert::IsTrue(pSCB->recvWindowExpectedSN == FIRST_SN + 1);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 0x10004);

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	// gap1: 1, data1: 2, gap2: 3~0x8002(inclusive), data2: 0x8003
	Assert::IsTrue(r == 2 && seq0 == FIRST_SN + 1
		&& gaps[0].gapWidth == 1 && gaps[0].dataLength == 1
		&& gaps[1].gapWidth == 0x8000 && gaps[1].dataLength == 1
	);

	// when a very large continuous data segment among small gaps
	for(int i = 4; i < 0x10003U; i++)
	{
		skb1 = socket.AllocRecvBuf(FIRST_SN + i);
		Assert::IsNotNull(skb1);
		skb1->opCode = PURE_DATA;
		skb1->ReInitMarkComplete();
	}
	Assert::IsTrue(pSCB->recvWindowExpectedSN == FIRST_SN + 1);

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 2 && seq0 == FIRST_SN + 1);

	int32_t nB;
	bool b;	// Used to be test for 'To be Continued', now for 'End of Transaction'
	pSCB->InquireRecvBuf(r, nB, b);
	Assert::IsTrue(r == 1);
	Assert::IsTrue(b);
	pSCB->MarkReceivedFree(nB);
	Assert::IsTrue(pSCB->recvWindowHeadPos == 1 && pSCB->recvWindowFirstSN == (FIRST_SN + 1));
	Assert::IsTrue(pSCB->recvWindowExpectedSN == FIRST_SN + 1);

	skb1 = socket.AllocRecvBuf(FIRST_SN + 1);
	Assert::IsNotNull(skb1);
	skb1->opCode = PURE_DATA;
	skb1->ReInitMarkComplete();
	Assert::IsTrue(pSCB->recvWindowExpectedSN == FIRST_SN + 3);

	ControlBlock::PFSP_SocketBuf p = pSCB->HeadRecv();
	(++p)->len = MAX_BLOCK_SIZE;
	(++p)->len = MAX_BLOCK_SIZE;

	pSCB->InquireRecvBuf(r, nB, b);
	pSCB->MarkReceivedFree(nB);
	Assert::IsTrue(!b && r == MAX_BLOCK_SIZE * 2);	// position 0 skipped; position 3 is the gap

	skb1 = socket.AllocRecvBuf(FIRST_SN + 3);
	Assert::IsNotNull(skb1);
	skb1->opCode = PURE_DATA;
	skb1->ReInitMarkComplete();
	Assert::IsTrue(pSCB->recvWindowExpectedSN == FIRST_SN + 0x10004);

	for(int i = 0; i < 0x10000; i++, p++)	// position 3 to position 0x10002
	{
		p->len = MAX_BLOCK_SIZE;	// opCode has been set
	}
	p->InitMarkLocked(); // partial delivery should work

	int32_t m;
	void * buf = pSCB->InquireRecvBuf(m, nB, b);
	Assert::IsNotNull(buf);
	Assert::IsFalse(b);
	pSCB->MarkReceivedFree(nB);
	Assert::IsTrue(pSCB->recvWindowHeadPos == 0x10002 && pSCB->recvWindowFirstSN == (FIRST_SN + 0x10002));

	//
	skb1 = socket.AllocRecvBuf(FIRST_SN + 0x20001);
	Assert::IsTrue(pSCB->recvWindowExpectedSN == FIRST_SN + 0x10004);
	Assert::IsNotNull(skb1);
	skb1->opCode = PURE_DATA;
	skb1->ReInitMarkComplete();
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 0x20002);

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	// there's a continuous data block which is not delivered yet. however, it is not considered needing a gap descriptor
	Assert::IsTrue(r == 1 && seq0 == FIRST_SN + 0x10004);
	// because recvWindowExepctedSN has advanced to this position,
	// although packet descriptor at 0x10003's flag IS_FULFILLED was NOT set
	// gap: 0x10004~0x20000 (inclusive), data: 0x20001
	Assert::IsTrue(gaps[0].gapWidth == 0x20001 - 0x10004 && gaps[0].dataLength == 1);
}



void UnitTestPeerCommitted()
{
	CSocketItemExDbg socket(MAX_BLOCK_NUM, MAX_BLOCK_NUM);
	ControlBlock *pSCB = socket.GetControlBlock();
	pSCB->SetRecvWindow(FIRST_SN);
	//
	// TODO: put test data...
	ControlBlock::PFSP_SocketBuf skb = pSCB->AllocRecvBuf(FIRST_SN);

	//
	pSCB->PeerCommitted();
	// Assert::
}
