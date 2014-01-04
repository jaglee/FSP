#include "targetver.h"

#include "../FSP_SRV/fsp_srv.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <mstcpip.h>

// Headers for CppUnitTest
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "ntdll.lib")


#ifdef MAX_CONNECTION_NUM
#undef MAX_CONNECTION_NUM
#endif
#define MAX_CONNECTION_NUM	256

#define MAX_PHY_INTERFACES	4

// for line output
char linebuf[200];

class CSocketItemExDbg: public CSocketItemEx
{
public:
	CSocketItemExDbg()
	{
		hMemoryMap = NULL;
		hEvent = NULL;
		pControlBlock = (ControlBlock *)malloc
			(sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * 8);
		pControlBlock->Init(MAX_BLOCK_SIZE * 2, MAX_BLOCK_SIZE * 2);
	};
	CSocketItemExDbg(int nSend, int nRecv)
	{
		hMemoryMap = NULL;
		hEvent = NULL;
		pControlBlock = (ControlBlock *)malloc
			(sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * (nSend + nRecv));
		pControlBlock->Init(MAX_BLOCK_SIZE * nSend, MAX_BLOCK_SIZE * nRecv);
	};
	~CSocketItemExDbg()
	{
		free(pControlBlock);
	}
	void LOCALAPI ResetVMAC()
	{
		vhash_reset(& pControlBlock->mac_ctx);	// vmac_set_key
	}
	ControlBlock *GetControlBlock() const { return pControlBlock; }

	friend void UnitTestSocketInState();
	friend void UnitTestResendQueue();
};


// Just a test stub
void LOCALAPI CSocketItemEx::Connect(CommandNewSession *pCmd) { }


/**
 *
 */
int LOCALAPI CallbackReceived(void *c, void *s, int n)
{
	// do nothing else
	Assert::IsTrue(n > 0);
	return 0;
}



/**
 * Unit Test of:
 * InquireSendBuf
 * MarkSendQueue
 * InquireRecvBuf
 * FetchReceived
 * AllocRecvBuf
 * GetSelectiveNACK
 */
void UnitTestSendRecvWnd()
{
	int memsize = sizeof(ControlBlock) + (sizeof ControlBlock::FSP_SocketBuf + MAX_BLOCK_SIZE) * 8;
	const ControlBlock::seq_t FIRST_SN = 12;

	ControlBlock * pSCB = (ControlBlock *)malloc(memsize);
	pSCB->Init((memsize - sizeof(ControlBlock))/ 2, (memsize - sizeof(ControlBlock)) / 2);
	//pSCB->sendWindowSize = pSCB->sendBufferSize;	// shall do nothing with send buffer management
	//^ shall set to min(sendBufferSize, remoteReceiveWindowSize);

	// set the begin of the send sequence number for the test to work properly
	// set the negotiated receive window parameter
	pSCB->recvWindowFirstSN = pSCB->receiveMaxExpected = FIRST_SN;

	ControlBlock::PFSP_SocketBuf skb = pSCB->GetVeryFirstSendBuf(FIRST_SN);
	Assert::IsNotNull(skb);
	Assert::IsTrue(pSCB->sendBufferNextSN == FIRST_SN + 1);
	// TODO: SCB pointer to user space pointer
	// TODO: recalibrate pointer...
	// FSP_AffirmToConnect & request = *(FSP_AffirmToConnect *)(*pControlBlock)[skb];

	int m;
	void *inplaceBuf = pSCB->InquireSendBuf(m);
	Assert::IsNotNull(inplaceBuf);	// it might fail if memsize is too small
	Assert::IsTrue(m > 0);			// it might fail if memsize is too small
	if(m < MAX_BLOCK_SIZE * 2)
		return;

	m = MAX_BLOCK_SIZE * 2 - 13;	// deliberate take use of less than maximum capacity
	memset(inplaceBuf, 'F', m);
	int k = pSCB->MarkSendQueue(inplaceBuf, m, true);
	Assert::IsFalse(k > 0);
	k = pSCB->MarkSendQueue(inplaceBuf, m, false);
	Assert::IsTrue(k > 0);
	Assert::IsTrue(pSCB->sendBufferNextSN == FIRST_SN + 3);

	ControlBlock::PFSP_SocketBuf skb3 = pSCB->HeadSend() + 2;
	skb->SetFlag<IS_ACKNOWLEDGED>();
	skb3->SetFlag<IS_ACKNOWLEDGED>();

	// emulate received the first data packet
	ControlBlock::PFSP_SocketBuf skb4 = pSCB->AllocRecvBuf(FIRST_SN);
	Assert::IsNotNull(skb4);
	// TODO: SCB buffer pointer to user space pointer
	skb4->len = MAX_BLOCK_SIZE - 13;
	skb4->SetFlag<TO_BE_CONTINUED>(false);
	skb4->SetFlag<IS_COMPLETED>();

	int m2;	// onReturn it should == skb4->len, i.e. MAX_BLOCK_SIZE - 13
	bool toBeContinued;
	void *inplaceBuf2 = pSCB->InquireRecvBuf(m2, toBeContinued);
	Assert::IsNotNull(inplaceBuf2);
	Assert::IsTrue(m2 == MAX_BLOCK_SIZE - 13);
	Assert::IsTrue(pSCB->recvWindowFirstSN == FIRST_SN + 1);
	Assert::IsTrue(pSCB->receiveMaxExpected == FIRST_SN + 1);

	BYTE * stBuf = (BYTE *)_alloca(memsize >> 2);
	memset(stBuf, 'S', memsize >> 2);
	int m3 = pSCB->FetchReceived(stBuf, CallbackReceived);
	Assert::IsTrue(m3 <= 0);

	ControlBlock::PFSP_SocketBuf skb5 = pSCB->AllocRecvBuf(FIRST_SN);
	Assert::IsNull(skb5);	// out of order
	//
	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 6);
	Assert::IsTrue(skb5 != skb4);	// it depends that IsNull(skb5)

	// emulate a received message that crosses two packet
	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 1);
	Assert::IsNotNull(skb5);
	Assert::IsTrue(pSCB->receiveMaxExpected == FIRST_SN + 2);

	skb5->len = MAX_BLOCK_SIZE;
	skb5->SetFlag<TO_BE_CONTINUED>();
	skb5->SetFlag<IS_COMPLETED>();
	skb5->MarkInSending();

	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 2);
	Assert::IsNotNull(skb5);
	Assert::IsTrue(pSCB->receiveMaxExpected == FIRST_SN + 3);

	skb5->len = MAX_BLOCK_SIZE - 13;
	skb5->SetFlag<TO_BE_CONTINUED>(false);
	skb5->SetFlag<IS_COMPLETED>();
	skb5->MarkInSending();

	// emulate a received-ahead packet
	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 4);
	Assert::IsNotNull(skb5);
	Assert::IsTrue(pSCB->receiveMaxExpected == FIRST_SN + 5);

	skb5->len = MAX_BLOCK_SIZE - 13;
	skb5->SetFlag<TO_BE_CONTINUED>(false);
	skb5->SetFlag<IS_COMPLETED>();

	// what is the content of the selective negative acknowledgement?
	FSP_SelectiveNACK::GapDescriptor snack[4];
	ControlBlock::seq_t seq4;
	int m4 = pSCB->GetSelectiveNACK(seq4, snack, 4);
	Assert::IsTrue(m4 == 1 && snack[0].dataLength == 1 && snack[0].gapWidth == 1);
	Assert::IsTrue(seq4 == FIRST_SN + 5);

	// To support ReadFrom
	m3 = pSCB->FetchReceived(stBuf, CallbackReceived);
	Assert::IsTrue(m3 > 0);

	// Clean up
	free(pSCB);
}


/**
 * Unit Test of:
 * GetSendBuf
 * PeekNextToSend
 * AllocRecvBuf
 * GetSelectiveNACK
 * RespondSNACK
 * GetNextResend
 */
void UnitTestResendQueue()
{
	const ControlBlock::seq_t FIRST_SN = 12;
	CSocketItemExDbg lowSocket;
	int memsize = sizeof(ControlBlock) + (sizeof ControlBlock::FSP_SocketBuf + MAX_BLOCK_SIZE) * 8;
	memset(& lowSocket, 0, sizeof(CSocketItemExDbg));
	lowSocket.dwMemorySize = memsize;

	ControlBlock * pSCB = (ControlBlock *)malloc(lowSocket.dwMemorySize);
	lowSocket.pControlBlock = pSCB;

	pSCB->Init((memsize - sizeof(ControlBlock)) / 2, (memsize - sizeof(ControlBlock)) / 2);

	// set the begin of the send sequence number for the test to work properly
	// set the negotiated receive window parameter
	pSCB->recvWindowFirstSN = pSCB->receiveMaxExpected = FIRST_SN;

	ControlBlock::PFSP_SocketBuf skb = pSCB->GetVeryFirstSendBuf(FIRST_SN);
	skb->SetFlag<IS_COMPLETED>();
	Assert::IsTrue(pSCB->sendBufferNextSN == FIRST_SN + 1);


	skb = pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	Assert::IsTrue(pSCB->sendBufferNextSN == FIRST_SN + 2);

	skb = pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	Assert::IsTrue(pSCB->sendBufferNextSN == FIRST_SN + 3);

	skb = pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	Assert::IsTrue(pSCB->sendBufferNextSN == FIRST_SN + 4);

	skb = pSCB->GetSendBuf();
	Assert::IsNull(skb);	// as we knew there're only 4 packet slots 

	skb = pSCB->PeekNextToSend();
	Assert::IsTrue(skb == pSCB->HeadSend());

	++(pSCB->sendWindowNextSN);
	skb = pSCB->PeekNextToSend();
	Assert::IsTrue(skb == pSCB->HeadSend() + 1);

	++(pSCB->sendWindowNextSN);
	skb = pSCB->PeekNextToSend();
	Assert::IsTrue(skb == pSCB->HeadSend() + 2);

	++(pSCB->sendWindowNextSN);
	skb = pSCB->PeekNextToSend();
	Assert::IsTrue(skb == pSCB->HeadSend() + 3);

	++(pSCB->sendWindowNextSN);
	skb = pSCB->PeekNextToSend();
	Assert::IsNotNull(skb);
	// Unlike CSocketItemEx::PeekNextToSend, ControlBlock::PeekNextToSend does not check overflow
	// See also comment of ControlBlock::PeekNextToSend

	skb =  pSCB->HeadSend();
	skb->SetFlag<IS_ACKNOWLEDGED>();

	skb = pSCB->HeadSend() + 1;
	skb->SetFlag<IS_ACKNOWLEDGED>();

	// emulate received the first data packet
	ControlBlock::PFSP_SocketBuf skb5 = pSCB->AllocRecvBuf(FIRST_SN);
	Assert::IsNotNull(skb5);
	skb5->SetFlag<IS_COMPLETED>();

	// emulate a received message that crosses two packet
	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 1);
	Assert::IsNotNull(skb5);
	Assert::IsTrue(pSCB->receiveMaxExpected == FIRST_SN + 2);

	skb5->SetFlag<IS_COMPLETED>();

	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 3);
	Assert::IsNotNull(skb5);
	Assert::IsTrue(pSCB->receiveMaxExpected == FIRST_SN + 4);

	skb5->SetFlag<IS_COMPLETED>();

	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 4);
	Assert::IsNull(skb5);	// No more space in the receive buffer

	// what is the content of the selective negative acknowledgement?
	FSP_SelectiveNACK::GapDescriptor snack[4];
	ControlBlock::seq_t seq4;
	int m4 = pSCB->GetSelectiveNACK(seq4, snack, 4);
	Assert::IsTrue(m4 == 1 && snack[0].dataLength == 1 && snack[0].gapWidth == 1);
	Assert::IsTrue(seq4 == FIRST_SN + 4);

	lowSocket.RespondSNACK(seq4, snack, 1);

	// TODO: Test round-robin, by slide one...

	// free(pSCB);	// clean up work done by the destroyer of CSocketItemExDbg
}


#if 0	// Absolutely obsolete
/**
 * Auxilary test-stub class for test of session control block translate look aside buffer
 */
class CommandSyncSessionTestSub: public CommandSyncSession
{
public:
	CommandSyncSessionTestSub(ALT_ID_T id)
	{
		hMemoryMap = CreateFileMapping(INVALID_HANDLE_VALUE	// backed by the system paging file
			, NULL	// not inheritable
			, PAGE_READWRITE | SEC_COMMIT
			, 0, MAX_SHM_SIZE	// file mapping size, we limit it to less than 4GB
			, NULL);
		if(hMemoryMap == INVALID_HANDLE_VALUE || hMemoryMap == NULL)
		{
			REPORT_ERRMSG_ON_TRACE("Cannot create shared memory object by CreateFileMapping");
			throw E_ABORT;
		}

		szShMemory = MAX_SHM_SIZE;

		hEvent = CreateEvent(NULL
			, true // false // BOOL bManualReset
			, false // not signaled
			, NULL);	// "FlexibleSessionProtocolEvent"

		if(hEvent == INVALID_HANDLE_VALUE || hEvent == NULL)
		{
			REPORT_ERRMSG_ON_TRACE("Cannot create event object for reverse synchronization");
			CloseHandle(hMemoryMap);
			throw E_HANDLE;
		}

		idProcess = GetCurrentProcessId();	// it's OK to map one's own memory space twice
		idSession = id;
	}
};


/*
 * Section: CommandQuasiQ is not strictly a type of queue.
 * Instead, its item value might be set and accessed freely, and removal of item is by make a marking
 * However, management of the tail which is the postion that the new item is added is of queue-flavor
 */
void UnitTestCommandQuasiQ()
{
	CommandQuasiQ cqq;
	register int i;
	int n;
	FSPIPC::SRVNotice r;
	bool b;
	cqq.Init();

	b = cqq.SetReturned(FSPIPC::CallbackAccept, (FSPIPC::SRVNotice)0);
	Assert::IsFalse(b, L"Cannot set returned value before an entry added");
	b = cqq.Fetch(FSPIPC::CallbackAccept, & r);
	Assert::IsFalse(b, L"Cannot fetch returned value before value set");

	for(i = 0; i < MAX_BACKLOG_SIZE; i++)
	{
		n = cqq.Add(FSPIPC::CallbackAccept);
		sprintf_s(linebuf, sizeof(linebuf), "Added sequence number: %u\n", n);
		Logger::WriteMessage(linebuf);
	}
	n = cqq.Add(FSPIPC::CallbackAccept);
	Assert::AreEqual(0, n, L"Add should fail if it overflow");

	b = cqq.SetReturned(FSPIPC::CallbackAccept, (FSPIPC::SRVNotice)0);
	Assert::IsTrue(b);
	b = cqq.Fetch(FSPIPC::CallbackAccept, & r);
	Assert::IsTrue(b);

	sprintf_s(linebuf, sizeof(linebuf), "Returned value: %d\n", r);
	Logger::WriteMessage(linebuf);

	b = cqq.SetReturned(FSPIPC::InitConnection, (FSPIPC::SRVNotice)0);
	Assert::IsFalse(b, L"It should be able to set return value for non-existent operation");
	b = cqq.Fetch(FSPIPC::InitConnection, &r);
	Assert::IsFalse(b, L"There should be no return value for non-existent operation");

	n = cqq.Add(FSPIPC::InitConnection);

	sprintf_s(linebuf, sizeof(linebuf), "Added sequence number: %u\n", n);
	Logger::WriteMessage(linebuf);
	//
	b = cqq.SetReturned((UINT32)n, (FSPIPC::SRVNotice)2);
	Assert::IsTrue(b);
	b = cqq.Fetch((UINT32)n, & r);
	Assert::IsTrue(b);
	Assert::AreEqual(2, (int)r);

	cqq.SetReturned(FSPIPC::CallbackAccept, (FSPIPC::SRVNotice)-1);
	cqq.Fetch(FSPIPC::CallbackAccept, & r);

	sprintf_s(linebuf, sizeof(linebuf), "Returned value: %u\n", r);
	Logger::WriteMessage(linebuf);

	Assert::IsTrue(cqq.IsCommandQHeadFree(), L"All entries in the queue should have been popped out.");
	for(i = 0; i < MAX_BACKLOG_SIZE; i++)
	{
		n = cqq.Add(FSPIPC::CallbackAccept);
		sprintf_s(linebuf, sizeof(linebuf), "Added sequence number: %u\n", n);
		Logger::WriteMessage(linebuf);
	}

	for(i = 0; i < MAX_BACKLOG_SIZE; i++)
	{
		b = cqq.SetReturned(FSPIPC::CallbackAccept, (FSPIPC::SRVNotice)(i + 3));
		Assert::IsTrue(b);
		b = cqq.Fetch(FSPIPC::CallbackAccept, & r);
		Assert::IsTrue(b);
		Assert::AreEqual(i + 3, (int)r);
		//
		sprintf_s(linebuf, sizeof(linebuf), "Returned value: %u\n", r);
		Logger::WriteMessage(linebuf);
	}

	n = cqq.Add(FSPIPC::InitConnection);
	sprintf_s(linebuf, sizeof(linebuf), "Added sequence number: %u\n", n);
	Logger::WriteMessage(linebuf);
	//
	b = cqq.SetReturned((UINT32)n, (FSPIPC::SRVNotice)3);
	Assert::IsTrue(b);

	b = cqq.Fetch((UINT32)n, & r);
	Assert::IsTrue(b);
	Assert::AreEqual(3, (int)r);
	// TODO: test time-out, and more set/fetch value by sequence number[boundary check...]
}
#endif


void UnitTestBackLogs()
{
	static const int MAX_BACKLOG_SIZE = 4;
	static const int TEST_SIZE = sizeof(ControlBlock) + sizeof(BackLogItem) * MAX_BACKLOG_SIZE;
	ControlBlock *buf = (ControlBlock *)_alloca(TEST_SIZE);
	ControlBlock & cqq = *buf;
	BackLogItem item;
	register int i;
	int n;

	cqq.Init(MAX_BACKLOG_SIZE);
	n = cqq.PopBacklog(& item);
	Assert::IsTrue(n < 0, L"There should be no item to be popped");

	item.idRemote = 1234;
	item.salt = 4321;	// item.sessionKey[0] = 0xAA; // used to exploit session key
	for(i = 0; i < MAX_BACKLOG_SIZE; i++)
	{
		n = cqq.PushBacklog(& item);
		//
		sprintf_s(linebuf, sizeof(linebuf), "Insert at position %d\n", n);
		Logger::WriteMessage(linebuf);
	}
	n = cqq.PushBacklog(& item);
	Assert::IsTrue(n < 0, L"Cannot push into backlog when overflow");
	
	bool b = cqq.HasBacklog(& item);
	Assert::IsTrue(b, L"Cannot find the backlog item just put into the queue");

	item.salt = 3412;	// item.sessionKey[0] = 0xBB; // used to exploit session key
	b = cqq.HasBacklog(& item);
	Assert::IsFalse(b, L"Nonexistent backlog item should not be found");

	for(i = 0; i < MAX_BACKLOG_SIZE; i++)
	{
		n = cqq.PopBacklog(& item);
		//
		Assert::IsTrue(n >= 0, L"There should be log item popped");
		sprintf_s(linebuf, sizeof(linebuf), "Position at %d popped\n", n);
		Logger::WriteMessage(linebuf);
	}
	n = cqq.PopBacklog(& item);
	Assert::IsTrue(n < 0, L"Cannot popped when it is empty");
	//
	// change the length of the backlog queue on the fly
	//
	cqq.Init(MIN_QUEUED_INTR);
	n = cqq.PopBacklog(& item);
	Assert::IsTrue(n < 0, L"There should be no item to be popped");

	item.idRemote = 1234;
	item.salt = 4321;	// item.sessionKey[0] = 0xAA; // used to exploit session key
	for(i = 0; i < MIN_QUEUED_INTR; i++)
	{
		n = cqq.PushBacklog(& item);
		//
		sprintf_s(linebuf, sizeof(linebuf), "Insert at position %d\n", n);
		Logger::WriteMessage(linebuf);
	}
	n = cqq.PushBacklog(& item);
	Assert::IsTrue(n < 0, L"Cannot push into backlog when overflow");
	
	b = cqq.HasBacklog(& item);
	Assert::IsTrue(b, L"Cannot find the backlog item just put into the queue");

	item.salt = 3412;	// item.sessionKey[0] = 0xBB; // used to exploit session key
	b = cqq.HasBacklog(& item);
	Assert::IsFalse(b, L"Nonexistent backlog item should not be found");

	for(i = 0; i < MIN_QUEUED_INTR; i++)
	{
		n = cqq.PopBacklog(& item);
		//
		Assert::IsTrue(n >= 0, L"There should be log item popped");
		sprintf_s(linebuf, sizeof(linebuf), "Position at %d popped\n", n);
		Logger::WriteMessage(linebuf);
	}
	n = cqq.PopBacklog(& item);
	Assert::IsTrue(n < 0, L"Cannot popped when it is empty");
}



void UnitTestNoticeQ()
{
	ControlBlock *buf = (ControlBlock *)_alloca(sizeof(ControlBlock));
	ControlBlock & cqq = *buf;
	BackLogItem item;
	int n;

	memset(buf, 0, sizeof(ControlBlock));

	FSP_ServiceCode c = cqq.PopNotice();
	Assert::IsTrue(c == NullCommand, L"Nothing should be popped out from an empty queue");

	n = cqq.PushNotice(FSP_NotifyDisposed);		// 1
	Assert::IsFalse(n < 0, L"FSP_NotifyDisposed should have been pushed onto an empty queue");

	n = cqq.PushNotice(FSP_NotifyReset);		// 2
	Assert::IsFalse(n < 0, L"FSP_NotifyReset should have been pushed onto an un-fulfilled queue");

	n = cqq.PushNotice(FSP_NotifyDataReady);	// 3
	Assert::IsFalse(n < 0, L"FSP_NotifyDataReady should have been pushed onto an un-fulfilled queue");

	n = cqq.PushNotice(FSP_NotifyDataReady);
	Assert::IsFalse(n <= 0, L"Duplicated FSP_NotifyDataReady should be pushed onto queue with warning");

	n = cqq.PushNotice(FSP_NotifyReset);
	Assert::IsFalse(n <= 0, L"Duplicated FSP_NotifyReset should be pushed onto queue with warning");

	n = cqq.PushNotice(FSP_NotifyRecycled);		// 4
	Assert::IsFalse(n < 0, L"FSP_NotifyRecycled should have been pushed onto an un-fulfilled queue");

	n = cqq.PushNotice(FSP_NotifyAdjourn);		// 5
	Assert::IsFalse(n < 0, L"FSP_NotifyAdjourn should have been pushed onto an un-fulfilled queue");

	n = cqq.PushNotice(FSP_NotifyFlushed);		// 6
	Assert::IsFalse(n < 0, L"FSP_NotifyFlushed should have been pushed onto an un-fulfilled queue");

	n = cqq.PushNotice(FSP_NotifyBufferReady);	// 7
	Assert::IsFalse(n < 0, L"FSP_NotifyBufferReady should have been pushed onto an un-fulfilled queue");

	n = cqq.PushNotice(FSP_NotifyDisposed);
	Assert::IsFalse(n <= 0, L"Duplicated FSP_NotifyDisposed should be pushed onto queue with warning");

	n = cqq.PushNotice(FSP_NotifyIOError);		// 8
	Assert::IsFalse(n < 0, L"FSP_NotifyIOError should have been pushed onto an un-fulfilled queue");

	n = cqq.PushNotice(FSP_NotifyOverflow);
	Assert::IsTrue(n < 0, L"FSP_NotifyOverflow should have failed to be pushed onto a fulfilled queue");

	n = cqq.PushNotice(FSP_NotifyNameResolutionFailed);
	Assert::IsTrue(n < 0, L"FSP_NotifyNameResolutionFailed should have failed to be pushed onto a fulfilled queue");

	// 
	c = cqq.PopNotice();	// 1
	Assert::IsTrue(c == FSP_NotifyDisposed, L"What is popped should be what was pushed 1st");

	c = cqq.PopNotice();	// 2
	Assert::IsTrue(c == FSP_NotifyReset, L"What is popped should be what was pushed 2nd");

	c = cqq.PopNotice();	// 3
	Assert::IsTrue(c == FSP_NotifyDataReady, L"What is popped should be what was pushed 3rd");

	c = cqq.PopNotice();	// 4
	Assert::IsTrue(c == FSP_NotifyRecycled, L"What is popped should be what was pushed 4th");

	c = cqq.PopNotice();	// 5
	Assert::IsTrue(c == FSP_NotifyAdjourn, L"What is popped should be what was pushed 5th");

	c = cqq.PopNotice();	// 6
	Assert::IsTrue(c == FSP_NotifyFlushed, L"What is popped should be what was pushed 6th");

	c = cqq.PopNotice();	// 7
	Assert::IsTrue(c == FSP_NotifyBufferReady, L"What is popped should be what was pushed 7th");

	c = cqq.PopNotice();	// 8
	Assert::IsTrue(c == FSP_NotifyIOError, L"What is popped should be what was pushed 8th");

	c = cqq.PopNotice();
	Assert::IsTrue(c == NullCommand, L"NullCommand should be popped from an empty queue");
}


#if 0	// now we make our mind to exploit VMAC
void UnitTestGMAC()
{
	FSP_InitiateRequest request;
	FSP_Challenge responseZero;	// zero hint no state
	FSP_AffirmToConnect affirmedRequest;
	CtrlMsgHdr nearEnd;

	timestamp_t t0 = GetCurrentTimeIn100Nano();
	request.timeStamp = htonll(t0);
	rand_s((unsigned int *)& request.initCheckCode);
	rand_s((unsigned int *)& request.initCheckCode + 1);
	rand_s(& request.salt);
	request.hs.Set<FSP_InitiateRequest, INIT_CONNECT>();

	timestamp_t t1 = GetCurrentTimeIn100Nano();
	responseZero.initCheckCode = request.initCheckCode;
	(ALT_ID_T &)responseZero.timeDelta = htonl(LAST_WELL_KNOWN_ALT_ID); 
	EvaluateCookie(responseZero, t1, & nearEnd);

	responseZero.timeDelta = htonl((u_long)(t1 - t0)); 
	responseZero.cookie ^= ((UINT64)request.salt << 32) | request.salt;
	responseZero.hs.Set<FSP_Challenge, ACK_INIT_CONNECT>();

	affirmedRequest.cookie = responseZero.cookie ^ (((UINT64)request.salt << 32) | request.salt);
	affirmedRequest.initCheckCode = request.initCheckCode;
	affirmedRequest.idALT = htonl(LAST_WELL_KNOWN_ALT_ID);
	affirmedRequest.hs.Set<CONNECT_REQUEST>(sizeof(affirmedRequest));
	affirmedRequest.exTimeStamp.timeStamp = htonll(t0);
	affirmedRequest.exTimeStamp.timeDelta = htonl((u_long)(t1 - t0));
	affirmedRequest.exTimeStamp.hs.Set<FSP_Challenge, TIMESTAMP_DELTA>();
	bool b = ValidateCookie(affirmedRequest, & nearEnd);
	Assert::IsTrue(b == true);
}
#endif



void UnitTestVMAC()
{
	FSP_InitiateRequest request;
	FSP_Challenge responseZero;	// zero hint no state
	FSP_AckConnectRequest acknowledgement;
	CtrlMsgHdr nearEnd;

	timestamp_t t0 = NowUTC();
	request.timeStamp = htonll(t0);
	// initCheckCode, salt should be random, but remain as-is for test purpose
	request.hs.Set<FSP_InitiateRequest, INIT_CONNECT>();

	timestamp_t t1 = NowUTC();
	struct _CookieMaterial cm;
	cm.idALT = nearEnd.u.idALT;
	cm.idListener = htonl(LAST_WELL_KNOWN_ALT_ID);
	// the cookie depends on the listening session ID AND the responding session ID
	cm.salt = request.salt;
	responseZero.initCheckCode = request.initCheckCode;
	responseZero.cookie = CalculateCookie((BYTE *) & cm, sizeof(cm), t1);
	responseZero.timeDelta = htonl((u_long)(t1 - t0)); 
	responseZero.cookie ^= ((UINT64)request.salt << 32) | request.salt;
	responseZero.hs.Set<FSP_Challenge, ACK_INIT_CONNECT>();

	acknowledgement.expectedSN = 1;
	acknowledgement.sequenceNo = 1;
	acknowledgement.integrity.id.dstSessionID = htonl(LAST_WELL_KNOWN_ALT_ID); 
	acknowledgement.integrity.id.srcSessionID = nearEnd.u.idALT;

	memset(acknowledgement.encrypted, 0, sizeof(acknowledgement.encrypted));
	acknowledgement.hsKey.Set<EPHEMERAL_KEY>(sizeof(FSP_NormalPacketHeader));
	// should the connect parameter header. but it doesn't matter
	acknowledgement.hs.Set<FSP_AckConnectRequest, ACK_CONNECT_REQUEST>();

	PairSessionID savedId = acknowledgement.integrity.id;
	CSocketItemExDbg socket;
	socket.ResetVMAC();

	socket.SetIntegrityCheckCode(& acknowledgement);

	UINT64 savedICC = acknowledgement.integrity.code;
	acknowledgement.integrity.id = savedId;
	socket.SetIntegrityCheckCode(& acknowledgement);
	Assert::AreEqual<UINT64>(savedICC, acknowledgement.integrity.code);

	BYTE ackbuf[sizeof(acknowledgement) + 5];
	// suppose a misalignment found..
	memcpy(ackbuf + 3, & acknowledgement, sizeof(acknowledgement));
	FSP_AckConnectRequest & ack2 = *(FSP_AckConnectRequest *)(ackbuf + 3);

	ack2.integrity.id = savedId;
	socket.SetIntegrityCheckCode(& ack2);
	Assert::AreEqual<UINT64>(savedICC, ack2.integrity.code);
}



void UnitTestQuasibitfield()
{
	FSP_AckConnectRequest acknowledgement;

	acknowledgement.SetRecvWS(0x1);
	Assert::IsTrue(acknowledgement.flags_ws[0] == 0
		&& acknowledgement.flags_ws[1] == 0
		&& acknowledgement.flags_ws[2] == 1);
	acknowledgement.SetRecvWS(0x201);
	Assert::IsTrue(acknowledgement.flags_ws[0] == 0
		&& acknowledgement.flags_ws[1] == 2
		&& acknowledgement.flags_ws[2] == 1);
	acknowledgement.SetRecvWS(0x30201);
	Assert::IsTrue(acknowledgement.flags_ws[0] == 3
		&& acknowledgement.flags_ws[1] == 2
		&& acknowledgement.flags_ws[2] == 1);
	acknowledgement.SetRecvWS(0x4030201);
	Assert::IsTrue(acknowledgement.flags_ws[0] == 3
		&& acknowledgement.flags_ws[1] == 2
		&& acknowledgement.flags_ws[2] == 1);

	acknowledgement.ClearFlags();

	acknowledgement.SetFlag<ToBeContinued>();
	Assert::AreEqual<int>(acknowledgement.GetFlag<ToBeContinued>(), 1);
	acknowledgement.SetFlag<Compressed>();
	Assert::IsTrue(acknowledgement.flags_ws[3] == 3);
	acknowledgement.SetFlag<ExplicitCongestion>();
	Assert::IsTrue(acknowledgement.flags_ws[3] == 131);
	Assert::AreEqual<int>(acknowledgement.GetFlag<Compressed>(), 2);
	Assert::AreEqual<int>(acknowledgement.GetFlag<ExplicitCongestion>(), 128);
	//
	acknowledgement.ClearFlag<ToBeContinued>();
	Assert::IsTrue(acknowledgement.flags_ws[3] == 130);
	acknowledgement.ClearFlag<Compressed>();
	Assert::IsTrue(acknowledgement.flags_ws[3] == 128);
	acknowledgement.ClearFlag<ExplicitCongestion>();
	Assert::IsTrue(acknowledgement.flags_ws[3] == 0);
}



void UnitTestGenerateSNACK()
{
	static const ControlBlock::seq_t FIRST_SN = 12;
	static const int MAX_GAPS_NUM = 2;
	static const int MAX_BLOCK_NUM = 0x20000;	// 65536 * 2

	CSocketItemExDbg socket(MAX_BLOCK_NUM, MAX_BLOCK_NUM);
	ControlBlock *pSCB = socket.GetControlBlock();
	pSCB->receiveMaxExpected = pSCB->recvWindowFirstSN = FIRST_SN;

	FSP_SelectiveNACK::GapDescriptor gaps[MAX_GAPS_NUM];
	ControlBlock::seq_t seq0;

	// firstly, without a gap
	int r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 0 && seq0 == FIRST_SN);

	// secondly, one gap only
	ControlBlock::PFSP_SocketBuf skb1 = socket.AllocRecvBuf(FIRST_SN);
	Assert::IsNotNull(skb1);
	Assert::IsTrue(pSCB->receiveMaxExpected == FIRST_SN + 1);
	skb1->SetFlag<IS_COMPLETED>();

	skb1 = socket.AllocRecvBuf(FIRST_SN + 2);
	Assert::IsNotNull(skb1);
	Assert::IsTrue(pSCB->receiveMaxExpected == FIRST_SN + 3);
	skb1->SetFlag<IS_COMPLETED>();

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 1 && seq0 == FIRST_SN + 3);

	// when a very large gap among small continuous data segments found
	skb1 = socket.AllocRecvBuf(FIRST_SN + 0x10003);
	skb1->SetFlag<IS_COMPLETED>();
	Assert::IsNotNull(skb1);
	Assert::IsTrue(pSCB->receiveMaxExpected == FIRST_SN + 0x10004);

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 1 && seq0 == FIRST_SN + 3);

	// when gap descriptors overflow
	skb1 = socket.AllocRecvBuf(FIRST_SN + 0x8003);
	skb1->SetFlag<IS_COMPLETED>();
	Assert::IsNotNull(skb1);
	Assert::IsTrue(pSCB->receiveMaxExpected == FIRST_SN + 0x10004);

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 2 && seq0 == FIRST_SN + 0x8004);

	// when a very large continuous data segment among small gaps
	for(int i = 4; i < 0x10003; i++)
	{
		skb1 = socket.AllocRecvBuf(FIRST_SN + i);
		skb1->SetFlag<IS_COMPLETED>();
		Assert::IsNotNull(skb1);
	}

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 1 && seq0 == FIRST_SN + 3);

	bool b;
	pSCB->InquireRecvBuf(r, b);
	Assert::IsFalse(b);
	Assert::IsTrue(pSCB->recvWindowHeadPos == 1 && pSCB->recvWindowFirstSN == (FIRST_SN + 1));

	skb1 = socket.AllocRecvBuf(FIRST_SN + 1);
	skb1->SetFlag<IS_COMPLETED>();

	ControlBlock::PFSP_SocketBuf p = pSCB->HeadRecv();
	for(int i = 0; i < 0x10001; i++)
	{
		p->len = MAX_BLOCK_SIZE;
		(p++)->SetFlag<TO_BE_CONTINUED>();
	}

	pSCB->InquireRecvBuf(r, b);
	Assert::IsTrue(b && r == 0x400);

	skb1 = socket.AllocRecvBuf(FIRST_SN + 3);
	skb1->SetFlag<IS_COMPLETED>();
	skb1->SetFlag<TO_BE_CONTINUED>();

	pSCB->InquireRecvBuf(r, b);
	Assert::IsFalse(b);
	Assert::IsTrue(pSCB->recvWindowHeadPos == 0x10002 && pSCB->recvWindowFirstSN == (FIRST_SN + 0x10002));

	//
	skb1 = socket.AllocRecvBuf(FIRST_SN + 0x20001);
	skb1->SetFlag<IS_COMPLETED>();
	Assert::IsTrue(pSCB->receiveMaxExpected == FIRST_SN + 0x20002);

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	// there's a continuous data block which is not delivered yet. however, it is not considered needing a gap descriptor
	Assert::IsTrue(r == 1 && seq0 == FIRST_SN + 0x20002);
}



void UnitTestAcknowledge()
{
	static const ControlBlock::seq_t FIRST_SN = 12;
	static const int MAX_GAPS_NUM = 2;
	static const int MAX_BLOCK_NUM = 0x20000;	// 65536 * 2

	CSocketItemExDbg socket(MAX_BLOCK_NUM, MAX_BLOCK_NUM);
	ControlBlock *pSCB = socket.GetControlBlock();
	FSP_SelectiveNACK::GapDescriptor gaps[MAX_GAPS_NUM];

	pSCB->sendBufferNextSN = pSCB->sendWindowExpectedSN = pSCB->sendWindowNextSN = pSCB->sendWindowFirstSN = FIRST_SN;

	// A NULL acknowledgement, Keep-Alive
	int r = socket.RespondSNACK(FIRST_SN, NULL, 0);
	Assert::IsTrue(r == 0 && pSCB->sendBufferNextSN == pSCB->sendWindowFirstSN);
	Assert::IsTrue(pSCB->sendWindowFirstSN == FIRST_SN);

	ControlBlock::PFSP_SocketBuf skb = pSCB->GetVeryFirstSendBuf(FIRST_SN);
	Assert::IsNotNull(skb);
	Assert::IsTrue(pSCB->sendWindowSize == 1);	// set by GetVeryFirstSendBuf
	Assert::IsTrue(pSCB->sendBufferNextSN == FIRST_SN + 1);
	skb->SetFlag<IS_COMPLETED>();
	skb->MarkInSending();

	skb = pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	skb->MarkInSending();
	pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	skb->MarkInSending();
	Assert::IsTrue(pSCB->sendBufferNextSN == FIRST_SN + 3);

	// emulate sending, together with setting skb->timeOut
	// assume 3 packets sent
	pSCB->sendWindowNextSN += 3;
	pSCB->sendWindowSize = MAX_BLOCK_NUM;	// don't let size of send window limit the test
	Assert::IsTrue(pSCB->sendWindowNextSN == FIRST_SN + 3);

	// acknowledge the first two
	r = socket.RespondSNACK(FIRST_SN + 2, NULL, 0);
	Assert::IsTrue(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 2);
	Assert::IsTrue(pSCB->sendWindowSize == MAX_BLOCK_NUM - 2);

	// Now, more test...
	for(int i = 3; i < MAX_BLOCK_NUM; i++)
	{
		skb = pSCB->GetSendBuf();
		Assert::IsTrue(skb != NULL);
		skb->SetFlag<IS_COMPLETED>();
		skb->MarkInSending();
	}
	pSCB->sendWindowNextSN += MAX_BLOCK_NUM - 3;
	Assert::IsTrue(pSCB->sendWindowNextSN == FIRST_SN + MAX_BLOCK_NUM);

	// All buffer blocks should have been consumed after the two acknowledged have been allocated
	// [however, sendWindowSize is not reduced yet]
	skb = pSCB->GetSendBuf();	// the two acknowledged
	skb->SetFlag<IS_COMPLETED>();
	skb = pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	skb = pSCB->GetSendBuf();	// no space in the send buffer.
	Assert::IsTrue(skb == NULL);
	Assert::IsTrue(pSCB->sendWindowSize == MAX_BLOCK_NUM - 2);

	// assume the third is a gap...
	gaps[0].dataLength = 1;
	gaps[0].gapWidth = 1;
	// this is an illegal one
	r = socket.RespondSNACK(FIRST_SN, gaps, 1);
	Assert::IsTrue(r == -EBADF && pSCB->sendWindowFirstSN == FIRST_SN + 2);
	// again, an outdated one
	r = socket.RespondSNACK(FIRST_SN + 2, gaps, 1);
	Assert::IsTrue(r == -EDOM && pSCB->sendWindowFirstSN == FIRST_SN + 2);

	// this is a legal one
	r = socket.RespondSNACK(FIRST_SN + 5, gaps, 1);
	Assert::IsTrue(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 3);

	// this is a legal but redundant two gaps
	gaps[1].dataLength = 1;
	gaps[1].gapWidth = 1;
	r = socket.RespondSNACK(FIRST_SN + 5, gaps, 2);
	Assert::IsTrue(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 3);

	// two gaps, overlap with previous one [only to urge retransmission of those negatively acknowledged]
	r = socket.RespondSNACK(FIRST_SN + 7, gaps, 2);
	Assert::IsTrue(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 3);

	// two gaps, do real new acknowledgement
	r = socket.RespondSNACK(FIRST_SN + 9, gaps, 2);
	Assert::IsTrue(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 5);

	// a very large continuous data segment is acknowledged
	r = socket.RespondSNACK(FIRST_SN + 0x1000A, gaps, 2);
	Assert::IsTrue(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 0x10006);
	Assert::IsTrue(pSCB->sendWindowSize == MAX_BLOCK_NUM - 0x10006);

	// Test round-robin...
	for(int i = MAX_BLOCK_NUM + 2; i < MAX_BLOCK_NUM + 0x10000; i++)
	{
		skb = pSCB->GetSendBuf();
		Assert::IsTrue(skb != NULL);
		skb->SetFlag<IS_COMPLETED>();
		skb->MarkInSending();
	}
	pSCB->sendWindowNextSN += 0x10000;	// queuing to send is not the same as sending

	// an even larger continuous data segment is acknowledged
	r = socket.RespondSNACK(FIRST_SN + MAX_BLOCK_NUM + 0xF000, gaps, 2);
	Assert::IsTrue(r == 0 && pSCB->sendWindowHeadPos == 0xEFFC);
	Assert::IsTrue(pSCB->sendWindowSize == - 0xEFFC);	// overflow, but don't care!
	Assert::IsTrue(pSCB->sendWindowFirstSN == FIRST_SN + MAX_BLOCK_NUM + 0xEFFC);

	// TODO: Test calculation of RTT and Keep alive timeout 
}



void UnitTestSocketInState()
{
	CSocketItemExDbg socket(2, 2);
	socket.SetState(QUASI_ACTIVE);
	bool r = socket.InStates(3, PAUSING, RESUMING, QUASI_ACTIVE);
	Assert::IsTrue(r);
	socket.SetState(CLOSABLE);
	r = socket.InStates(4, PAUSING, RESUMING, QUASI_ACTIVE, CLOSED);
	Assert::IsFalse(r);
}




void UnitTestSocketSrvTLB()
{
	try
	{
		new CLowerInterface();
	}
	catch(HRESULT x)
	{
		sprintf_s(linebuf, sizeof(linebuf), "Exception number 0x%X, cannot access lower interface, aborted.\n", x); 
		Logger::WriteMessage(linebuf);

		DbgRaiseAssertionFailure();
	}

	CSocketItemEx *p1 = (CSocketItemEx *)(CLowerInterface::Singleton())->AllocItem(2);
	Assert::IsNotNull(p1, L"There should be free item slot for listener");

	CSocketItemEx *p = (CSocketItemEx *)(*CLowerInterface::Singleton())[2];
	Assert::IsTrue(p == p1, L"The remapped listening socket should be the same as the allocated");

	p = (CSocketItemEx *)(CLowerInterface::Singleton())->AllocItem();
	Assert::IsNotNull(p, L"There should be free item slot");

	IN6_ADDR addrList[MAX_PHY_INTERFACES];
	// no hint
	memset(addrList, 0, sizeof(addrList));
	ALT_ID_T id = (CLowerInterface::Singleton())->RandALT_ID();
	Assert::IsFalse(id == 0, L"There should be free id space");

	id = (CLowerInterface::Singleton())->RandALT_ID(addrList);
	Assert::IsFalse(id == 0, L"There should be free id space");

	sprintf_s(linebuf, "Allocated ID = %d\n", id);
	Logger::WriteMessage(linebuf);

#if 0
	for(int i = 0; i < MAX_PHY_INTERFACES; i++)
	{
		RtlIpv6AddressToString(& addrList[i], linebuf);
		Logger::WriteMessage(linebuf);
	}
#endif

	CSocketItemEx *p2 = (CSocketItemEx *)(*CLowerInterface::Singleton())[id];
	Assert::IsFalse(p2 == p1, L"RandID shouldn't alloc the same item as AllocItem for listener");
	Assert::IsFalse(p2 == p, L"RandID shouldn't alloc the same item as AllocItem");

	(CLowerInterface::Singleton())->FreeItem(p1);
	(CLowerInterface::Singleton())->FreeItem(p);
	(CLowerInterface::Singleton())->FreeItem(p2);

#if 0	// should invent another test method
	CommandSyncSessionTestSub *pCmd = new CommandSyncSessionTestSub(id);
	p = (*CLowerInterface::Singleton())[*pCmd];
	Assert::IsNotNull(p, L"There should be available socket to welcome connection");
#endif
}





#if 0	// obsolete
void UnitTestDerivedClass()
{
	FSPoverUDP_Header hdr;
	memset(& hdr, 0, sizeof(hdr));
	hdr.srcSessionID = 1;
	hdr.dstSessionID = 2;

	sprintf(linebuf, "Size of derived struct: %d\n", sizeof(hdr));
	Logger::WriteMessage(linebuf);

	FSP_Header & r = (FSP_Header &)hdr;
	sprintf(linebuf, "Size of base struct: %d\n", sizeof(r));
	Logger::WriteMessage(linebuf);

	Assert::IsFalse(sizeof(hdr) == sizeof((FSP_Header)hdr));
};
#endif



class CLowerInterfaceDbg: public CLowerInterface
{
public:
	BYTE *	CurrentHead() { return bufferMemory + sizeof(PktSignature) + bufHead; }
	friend	void UnitTestReceiveQueue();
};



void UnitTestReceiveQueue()
{
	CLowerInterfaceDbg *pLowerSrv = (CLowerInterfaceDbg *)CLowerInterface::Singleton();
	try
	{
		if(pLowerSrv == NULL)
			pLowerSrv = new CLowerInterfaceDbg();
	}
	catch(HRESULT x)
	{
		sprintf_s(linebuf, sizeof(linebuf), "Exception number 0x%X, cannot access lower interface, aborted.\n", x); 
		Logger::WriteMessage(linebuf);

		DbgRaiseAssertionFailure();
	}
	CLowerInterfaceDbg & lowerSrv = *pLowerSrv;

	const int MAX_BLOCKS = MAX_BUFFER_MEMORY / (sizeof(PktSignature) + MAX_LLS_BLOCK_SIZE);
	BYTE *p0 = lowerSrv.BeginGetBuffer();
	BYTE *p = p0;
	for(int i = 0; i < MAX_BLOCKS; i++)
	{
		Assert::IsTrue(p != NULL);
		lowerSrv.CommitGetBuffer(p, MAX_LLS_BLOCK_SIZE - 3);
		Assert::IsTrue(((PktSignature *)p - 1)->size == MAX_LLS_BLOCK_SIZE + 1);
		p = lowerSrv.BeginGetBuffer();
	}
	Assert::IsTrue(p == NULL);
	//
	p = p0;
	for(int i = 0; i < MAX_BLOCKS; i++)
	{
		lowerSrv.FreeBuffer(p);
		p += MAX_LLS_BLOCK_SIZE + sizeof(PktSignature);
		Assert::IsTrue(p == lowerSrv.CurrentHead());
	}
}



void UnitTestConnectQueue()
{
	static ConnectRequestQueue commandRequests;
	CommandNewSession t;
	t.opCode = InitConnection;

	int i = commandRequests.Push(& t);
	Assert::IsTrue(i >= 0);
	i = commandRequests.Remove(i);
	Assert::IsTrue(i >= 0);
}


void UnitTestHeaderManager()
{
#if 0
	CSocketItemExDbg 

	FSP_SelectiveNACK snack(sizeof(FSP_NormalPacketHeader));
	skb->opCode = ADJOURN;
	skb->len = hdrManager.PushExtHeader<FSP_SelectiveNACK>(& snack);
	welcome.hs.Set<ADJOURN>(skb->len);


	FSP_Header_Manager hdrManager((FSP_Header *) & response);
	UINT16 spFull = ntohs(response.hs.hsp);
	FSP_ConnectParam *pVarParams;
	hdrManager.PopExtHeader<FSP_ConnectParam>(& pVarParams);

	memset(rIPS.allowedPrefixes, 0, sizeof(rIPS.allowedPrefixes));
	// assert(sizeof(rIPS.allowedPrefixes) >= sizeof(pVarParams->subnets));
	memcpy(rIPS.allowedPrefixes, pVarParams->subnets, sizeof(pVarParams->subnets));

	FSP_Header_Manager hdrManager((FSP_Header *) & pkt);
	PFSP_HeaderSignature optHdr = hdrManager.PopExtHeader();
	if(optHdr->opCode == SELECTIVE_NACK)
	{
		FSP_SelectiveNACK::GapDescriptor *gaps = (FSP_SelectiveNACK::GapDescriptor *)((BYTE *) & pkt + ntohs(optHdr->hsp));
		FSP_SelectiveNACK *pHdr = (FSP_SelectiveNACK *)((BYTE *)optHdr + sizeof(*optHdr) - sizeof(*pHdr));
		int n = int((BYTE *)gaps - (BYTE *)pHdr);
		if(n < 0)
			return;	// this is a malformed packet. UNRESOLVED! Just silently discard it?	
		n /= sizeof(FSP_SelectiveNACK::GapDescriptor);
		if(pHdr->lastGap != 0)
			n ++;
		for(register int i = n - 1; i >= 0; i --)
		{
			gaps[i].gapWidth = ntohs(gaps[i].gapWidth);
			gaps[i].dataLength = ntohs(gaps[i].dataLength);
		}
		//
		pSocket->Acknowledge(ackSeqNo, gaps, n);
		optHdr = hdrManager.PopExtHeader();
	}

	// Conver the FSP header stack pointer to a data block pointer
	void * TopAsDataBlock() const { return pHdr + pStackPointer; }

	void PushDataBlock(BYTE *buf, int len)
#endif
}



namespace UnitTestFSP
{		
	TEST_CLASS(UnitTest1)
	{
	public:
#if 0		
		TEST_METHOD(TestCommandQuasiQ)
		{
			UnitTestCommandQuasiQ();
		}
#endif
		TEST_METHOD(TestBackLogs)
		{
			UnitTestBackLogs();
		}

		TEST_METHOD(TestNoticeQ)
		{
			UnitTestNoticeQ();
		}
#if 0
		TEST_METHOD(TestGMAC)
		{
			UnitTestGMAC();
		}
#endif

		TEST_METHOD(TestVMAC)
		{
			UnitTestVMAC();
		}


		TEST_METHOD(TestQuasibitfield)
		{
			UnitTestQuasibitfield();
		}

		
		TEST_METHOD(TestSocketSrvTLB)
		{
			UnitTestSocketSrvTLB();
		}


		TEST_METHOD(TestReceiveQueue)
		{
			UnitTestReceiveQueue();
		}


		TEST_METHOD(TestConnectQueue)
		{
			UnitTestConnectQueue();
		}

#if 0
		TEST_METHOD(DerivedClass)
		{
			UnitTestDerivedClass();
		}
#endif
		TEST_METHOD(TestSendRecvWnd)
		{
			UnitTestSendRecvWnd();
		}

		TEST_METHOD(TestResendQueue)
		{
			UnitTestResendQueue();
		}

		TEST_METHOD(TestGenerateSNACK)
		{
			UnitTestGenerateSNACK();
		}

		TEST_METHOD(TestAcknowledge)
		{
			UnitTestAcknowledge();
		}


		TEST_METHOD(TestSocketInState)
		{
			UnitTestSocketInState();
		}


		TEST_METHOD(TestHeaderManager)
		{
			UnitTestHeaderManager();
		}
	};
}
