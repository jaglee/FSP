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
	const ControlBlock::seq_t FIRST_SN = 12;

	ControlBlock *pSCB = (ControlBlock *)malloc(memsize);
	pSCB->Init((memsize - sizeof(ControlBlock))/ 2, (memsize - sizeof(ControlBlock)) / 2);
	//pSCB->sendWindowSize = pSCB->sendBufferSize;	// shall do nothing with send buffer management
	//^ shall set to min(sendBufferSize, remoteReceiveWindowSize);

	// set the begin of the send sequence number for the test to work properly
	// set the negotiated receive window parameter
	pSCB->SetRecvWindowHead(FIRST_SN);
	pSCB->SetSendWindowWithHeadReserved(FIRST_SN);
	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadSend();
	Assert::IsNotNull(skb);
	Assert::IsTrue(pSCB->sendBufferNextSN == FIRST_SN + 1);
	// TODO: SCB pointer to user space pointer
	// TODO: recalibrate pointer...
	// FSP_AffirmToConnect & request = *(FSP_AffirmToConnect *)(*pControlBlock)[skb];

	int m = MAX_BLOCK_SIZE;
	void *inplaceBuf = pSCB->InquireSendBuf(m);
	Assert::IsNotNull(inplaceBuf);	// it might fail if memsize is too small
	Assert::IsTrue(m > 0);			// it might fail if memsize is too small
	if(m < MAX_BLOCK_SIZE * 2)
		return;

	// TODO: UnitTest of SendInplace, SendStream

	ControlBlock::PFSP_SocketBuf skb3 = pSCB->HeadSend() + 2;
	skb->SetFlag<IS_ACKNOWLEDGED>();
	skb3->SetFlag<IS_ACKNOWLEDGED>();

	// emulate received the first data packet
	ControlBlock::PFSP_SocketBuf skb4 = pSCB->AllocRecvBuf(FIRST_SN);
	Assert::IsNotNull(skb4);
	Assert::IsTrue(pSCB->recvWindowFirstSN == FIRST_SN);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 1);
	// TODO: SCB buffer pointer to user space pointer
	skb4->len = MAX_BLOCK_SIZE - 13;
	skb4->SetFlag<TO_BE_CONTINUED>(false);
	skb4->SetFlag<IS_FULFILLED>();

	int m2;	// onReturn it should == skb4->len, i.e. MAX_BLOCK_SIZE - 13
	bool toBeContinued;
	void *inplaceBuf2 = pSCB->InquireRecvBuf(m2, toBeContinued);
	Assert::IsNotNull(inplaceBuf2);
	Assert::IsTrue(m2 == MAX_BLOCK_SIZE - 13);

	ControlBlock::PFSP_SocketBuf skb5 = pSCB->AllocRecvBuf(FIRST_SN);
	Assert::IsTrue(skb5 != skb4);	// out of order, and it depends that IsNull(skb5)
	//
	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 6);
	Assert::IsNull(skb5);			// no more advertised window space

	// emulate a received message that crosses two packet
	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 1);
	Assert::IsNotNull(skb5);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 2);

	skb5->len = MAX_BLOCK_SIZE;
	skb5->SetFlag<TO_BE_CONTINUED>();
	skb5->SetFlag<IS_FULFILLED>();
	skb5->Lock();

	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 2);
	Assert::IsNotNull(skb5);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 3);

	skb5->len = MAX_BLOCK_SIZE - 13;
	skb5->SetFlag<TO_BE_CONTINUED>(false);
	skb5->SetFlag<IS_FULFILLED>();
	skb5->Lock();

	// emulate a received-ahead packet
	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 4);
	Assert::IsNotNull(skb5);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 5);

	skb5->len = MAX_BLOCK_SIZE - 13;
	skb5->SetFlag<TO_BE_CONTINUED>(false);
	skb5->SetFlag<IS_FULFILLED>();

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
	while(p->GetFlag<IS_DELIVERED>())
	{
		pSCB->SlideRecvWindowByOne();
		p = pSCB->GetFirstReceived();
	}
	//
	while(p->GetFlag<IS_FULFILLED>() && !p->GetFlag<IS_DELIVERED>())
	{
		pSCB->SlideRecvWindowByOne();
		p->SetFlag<IS_DELIVERED>();	// so that it would not be re-delivered
		p->SetFlag<IS_FULFILLED>(false);	// so that it would not be re-delivered
		if(!p->GetFlag<TO_BE_CONTINUED>())
			break;
		p = pSCB->GetFirstReceived();
	}
	Assert::IsTrue(pSCB->recvWindowFirstSN == FIRST_SN + 3);

	skb4 = pSCB->AllocRecvBuf(FIRST_SN + 6);
	skb4->SetFlag<IS_FULFILLED>();
	skb4->len = MAX_BLOCK_SIZE - 13;
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
	pSCB->SetRecvWindowHead(FIRST_SN);

	FSP_SelectiveNACK::GapDescriptor gaps[MAX_GAPS_NUM];
	ControlBlock::seq_t seq0;

	// firstly, without a gap
	int r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 0 && seq0 == FIRST_SN);

	// secondly, one gap only
	ControlBlock::PFSP_SocketBuf skb1 = socket.AllocRecvBuf(FIRST_SN);
	Assert::IsNotNull(skb1);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 1);
	skb1->SetFlag<IS_FULFILLED>();

	skb1 = socket.AllocRecvBuf(FIRST_SN + 2);
	Assert::IsNotNull(skb1);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 3);
	skb1->SetFlag<IS_FULFILLED>();

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 1 && seq0 == FIRST_SN + 1);

	// when a very large gap among small continuous data segments found
	skb1 = socket.AllocRecvBuf(FIRST_SN + 0x10003);
	skb1->SetFlag<IS_FULFILLED>();
	Assert::IsNotNull(skb1);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 0x10004);

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 2 && seq0 == FIRST_SN + 1);

	// when capacity of gap descriptors overflow
	skb1 = socket.AllocRecvBuf(FIRST_SN + 0x8003);
	skb1->SetFlag<IS_FULFILLED>();
	Assert::IsNotNull(skb1);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 0x10004);

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 2 && seq0 == FIRST_SN + 1);

	// when a very large continuous data segment among small gaps
	for(int i = 4; i < 0x10003; i++)
	{
		skb1 = socket.AllocRecvBuf(FIRST_SN + i);
		Assert::IsNotNull(skb1);
		skb1->SetFlag<IS_FULFILLED>();
	}

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 2 && seq0 == FIRST_SN + 1);

	bool b;
	pSCB->InquireRecvBuf(r, b);
	Assert::IsFalse(b);
	Assert::IsTrue(pSCB->recvWindowHeadPos == 1 && pSCB->recvWindowFirstSN == (FIRST_SN + 1));

	skb1 = socket.AllocRecvBuf(FIRST_SN + 1);
	skb1->SetFlag<IS_FULFILLED>();

	ControlBlock::PFSP_SocketBuf p = pSCB->HeadRecv();
	for(int i = 0; i < 0x10001; i++)
	{
		p->len = MAX_BLOCK_SIZE;
		(p++)->SetFlag<TO_BE_CONTINUED>();
	}

	pSCB->InquireRecvBuf(r, b);
	Assert::IsTrue(b && r == MAX_BLOCK_SIZE * 2);

	skb1 = socket.AllocRecvBuf(FIRST_SN + 3);
	skb1->SetFlag<IS_FULFILLED>();
	skb1->SetFlag<TO_BE_CONTINUED>();

	pSCB->InquireRecvBuf(r, b);
	Assert::IsFalse(b);
	Assert::IsTrue(pSCB->recvWindowHeadPos == 0x10002 && pSCB->recvWindowFirstSN == (FIRST_SN + 0x10002));

	//
	skb1 = socket.AllocRecvBuf(FIRST_SN + 0x20001);
	skb1->SetFlag<IS_FULFILLED>();
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 0x20002);

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	// there's a continuous data block which is not delivered yet. however, it is not considered needing a gap descriptor
	Assert::IsTrue(r == 1 && seq0 == FIRST_SN + 0x10004);	// because +0x10003 has been assumed received
	// Dump the descriptor in the flow test which attaches a console.
}



void UnitTestHasBeenCommitted()
{
	CSocketItemExDbg socket(MAX_BLOCK_NUM, MAX_BLOCK_NUM);
	ControlBlock *pSCB = socket.GetControlBlock();
	pSCB->SetRecvWindowHead(FIRST_SN);
	//
	// TODO: put test data...
	ControlBlock::PFSP_SocketBuf skb = pSCB->AllocRecvBuf(FIRST_SN);

	//
	pSCB->HasBeenCommitted();
	// Assert::
}