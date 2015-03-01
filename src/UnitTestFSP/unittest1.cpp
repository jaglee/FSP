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
static char linebuf[200];


void UnitTestOpCodeStateNoticeNames()
{
	Logger::WriteMessage(opCodeStrings[-1]);
	Logger::WriteMessage(opCodeStrings[0]);
	Logger::WriteMessage(opCodeStrings[PERSIST]);
	Logger::WriteMessage(opCodeStrings[LARGEST_OP_CODE]);
	Logger::WriteMessage(opCodeStrings[LARGEST_OP_CODE + 1]);
	//
	Logger::WriteMessage(stateNames[-1]);
	Logger::WriteMessage(stateNames[0]);
	Logger::WriteMessage(stateNames[FSP_Session_State::COMMITTING]);
	Logger::WriteMessage(stateNames[CLOSED]);
	Logger::WriteMessage(stateNames[CLOSED + 1]);
	//
	Logger::WriteMessage(noticeNames[-1]);
	Logger::WriteMessage(noticeNames[0]);
	Logger::WriteMessage(noticeNames[FSP_ServiceCode::FSP_NotifyDataReady]);
	Logger::WriteMessage(noticeNames[FSP_ServiceCode::LARGEST_FSP_NOTICE]);
	Logger::WriteMessage(noticeNames[LARGEST_FSP_NOTICE + 1]);
}



class CSocketItemExDbg: public CSocketItemEx
{
public:
	CSocketItemExDbg()
	{
		// isMilky = 0;	// RespondSNACK cares it
		hMemoryMap = NULL;
		hEvent = NULL;
		pControlBlock = (ControlBlock *)malloc
			(sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * 8);
		pControlBlock->Init(MAX_BLOCK_SIZE * 2, MAX_BLOCK_SIZE * 2);
	};
	CSocketItemExDbg(int nSend, int nRecv)
	{
		// isMilky = 0;	// RespondSNACK cares it
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
	ControlBlock::PFSP_SocketBuf AllocRecvBuf(ControlBlock::seq_t seq1) { return pControlBlock->AllocRecvBuf(seq1); }

	friend void UnitTestSocketInState();
	friend void UnitTestReceiveQueue();
	friend void UnitTestResendQueue();
};


// Just test stubs
void CSocketItemEx::Connect() { }

CommandNewSessionSrv::CommandNewSessionSrv(const CommandToLLS *p1) { }

void CommandNewSessionSrv::DoConnect() { }



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

	BYTE * stBuf = (BYTE *)_alloca(memsize >> 2);
	memset(stBuf, 'S', memsize >> 2);
	//int m3 = pSCB->FetchReceived(stBuf, CallbackReceived);	// outdated
	//Assert::IsTrue(m3 <= 0);

	ControlBlock::PFSP_SocketBuf skb5 = pSCB->AllocRecvBuf(FIRST_SN);
	Assert::IsNull(skb5);	// out of order
	//
	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 6);
	Assert::IsTrue(skb5 != skb4);	// it depends that IsNull(skb5)

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
	Assert::IsTrue(m4 == 1 && snack[0].dataLength == 1 && snack[0].gapWidth == 1);
	Assert::IsTrue(seq4 == FIRST_SN + 5);

	// To support ReadFrom
	//m3 = pSCB->FetchReceived(stBuf, CallbackReceived);	// Outdated
	//Assert::IsTrue(m3 > 0);

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
	pSCB->recvWindowFirstSN = pSCB->recvWindowNextSN = FIRST_SN;

	pSCB->SetSendWindowWithHeadReserved(FIRST_SN);
	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadSend();
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

	//skb = pSCB->PeekNextToSend();
	//Assert::IsTrue(skb == pSCB->HeadSend());

	++(pSCB->sendWindowNextSN);
	//skb = pSCB->PeekNextToSend();
	//Assert::IsTrue(skb == pSCB->HeadSend() + 1);

	++(pSCB->sendWindowNextSN);
	//skb = pSCB->PeekNextToSend();
	//Assert::IsTrue(skb == pSCB->HeadSend() + 2);

	++(pSCB->sendWindowNextSN);
	//skb = pSCB->PeekNextToSend();
	//Assert::IsTrue(skb == pSCB->HeadSend() + 3);

	++(pSCB->sendWindowNextSN);
	//skb = pSCB->PeekNextToSend();
	//Assert::IsNull(skb);

	skb =  pSCB->HeadSend();
	//skb->SetFlag<IS_ACKNOWLEDGED>();

	//skb = pSCB->HeadSend() + 1;
	//skb->SetFlag<IS_ACKNOWLEDGED>();

	// emulate received the first data packet
	ControlBlock::PFSP_SocketBuf skb5 = pSCB->AllocRecvBuf(FIRST_SN);
	Assert::IsNotNull(skb5);
	skb5->SetFlag<IS_FULFILLED>();

	// emulate a received message that crosses two packet
	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 1);
	Assert::IsNotNull(skb5);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 2);

	skb5->SetFlag<IS_FULFILLED>();

	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 3);
	Assert::IsNotNull(skb5);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 4);

	skb5->SetFlag<IS_FULFILLED>();

	skb5 = pSCB->AllocRecvBuf(FIRST_SN + 4);
	Assert::IsNull(skb5);	// No more space in the receive buffer

	// what is the content of the selective negative acknowledgement?
	FSP_SelectiveNACK::GapDescriptor snack[4];
	ControlBlock::seq_t seq4;
	int m4 = pSCB->GetSelectiveNACK(seq4, snack, 4);
	Assert::IsTrue(m4 == 1 && snack[0].dataLength == 1 && snack[0].gapWidth == 1);
	Assert::IsTrue(seq4 == FIRST_SN + 4);

	lowSocket.RespondSNACK(seq4, snack, 1);
	Assert::IsTrue(skb->flags == 0);	// GetFlag<IS_ACKNOWLEDGED>()
	Assert::IsTrue((skb + 1)->flags == 0);	// GetFlag<IS_ACKNOWLEDGED>()
	Assert::IsTrue((skb + 3)->GetFlag<IS_ACKNOWLEDGED>());
	Assert::IsTrue(lowSocket.pControlBlock->sendWindowFirstSN == FIRST_SN + 2);

	// TODO: Test round-robin, by slide one...
	// TODO: change resend window size, test receive max expected SN
	// TODO: change send window initial size, slow-start? [slide-window based flow control/rate-control?]

	// free(pSCB);	// clean up work done by the destroyer of CSocketItemExDbg
}


#if 0	// Absolutely obsolete
/**
 * Auxilary test-stub class for test of session control block translate look aside buffer
 */
class CommandSyncSessionTestSub: public CommandSyncSession
{
public:
	CommandSyncSessionTestSub(ALFID_T id)
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
	int n;

	memset(buf, 0, sizeof(ControlBlock));

	FSP_ServiceCode c = cqq.PopNotice();
	Assert::IsTrue(c == NullCommand, L"Nothing should be popped out from an empty queue");

	n = cqq.PushNotice(FSP_NotifyTimeout);		// 1
	Assert::IsFalse(n < 0, L"FSP_NotifyTimeout should have been pushed onto an empty queue");

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

	n = cqq.PushNotice(FSP_NotifyAccepted);		// 5
	Assert::IsFalse(n < 0, L"FSP_NotifyAccepted should have been pushed onto an un-fulfilled queue");

	n = cqq.PushNotice(FSP_NotifyFlushed);		// 6
	Assert::IsFalse(n < 0, L"FSP_NotifyFlushed should have been pushed onto an un-fulfilled queue");

	n = cqq.PushNotice(FSP_NotifyBufferReady);	// 7
	Assert::IsFalse(n < 0, L"FSP_NotifyBufferReady should have been pushed onto an un-fulfilled queue");

	n = cqq.PushNotice(FSP_NotifyTimeout);
	Assert::IsFalse(n <= 0, L"Duplicated FSP_NotifyTimeout should be pushed onto queue with warning");

	n = cqq.PushNotice(FSP_IPC_CannotReturn);		// 8
	Assert::IsFalse(n < 0, L"FSP_IPC_CannotReturn should have been pushed onto an un-fulfilled queue");

	n = cqq.PushNotice(FSP_NotifyOverflow);
	Assert::IsTrue(n < 0, L"FSP_NotifyOverflow should have failed to be pushed onto a fulfilled queue");

	n = cqq.PushNotice(FSP_NotifyNameResolutionFailed);
	Assert::IsTrue(n < 0, L"FSP_NotifyNameResolutionFailed should have failed to be pushed onto a fulfilled queue");

	// 
	c = cqq.PopNotice();	// 1
	Assert::IsTrue(c == FSP_NotifyTimeout, L"What is popped should be what was pushed 1st");

	c = cqq.PopNotice();	// 2
	Assert::IsTrue(c == FSP_NotifyReset, L"What is popped should be what was pushed 2nd");

	c = cqq.PopNotice();	// 3
	Assert::IsTrue(c == FSP_NotifyDataReady, L"What is popped should be what was pushed 3rd");

	c = cqq.PopNotice();	// 4
	Assert::IsTrue(c == FSP_NotifyRecycled, L"What is popped should be what was pushed 4th");

	c = cqq.PopNotice();	// 5
	Assert::IsTrue(c == FSP_NotifyAccepted, L"What is popped should be what was pushed 5th");

	c = cqq.PopNotice();	// 6
	Assert::IsTrue(c == FSP_NotifyFlushed, L"What is popped should be what was pushed 6th");

	c = cqq.PopNotice();	// 7
	Assert::IsTrue(c == FSP_NotifyBufferReady, L"What is popped should be what was pushed 7th");

	c = cqq.PopNotice();	// 8
	Assert::IsTrue(c == FSP_IPC_CannotReturn, L"What is popped should be what was pushed 8th");

	c = cqq.PopNotice();
	Assert::IsTrue(c == NullCommand, L"NullCommand should be popped from an empty queue");
}


void UnitTestCubicRoot()
{
	Assert::IsTrue(fabs(CubicRoot(0)) < DBL_EPSILON);
	Assert::IsTrue(fabs(CubicRoot(-1) + 1) < DBL_EPSILON);
	Assert::IsTrue(fabs(CubicRoot(1) - 1) < DBL_EPSILON);
	Assert::IsTrue(fabs(CubicRoot(0.001) - 0.1) < DBL_EPSILON);
	Assert::IsTrue(fabs(CubicRoot(8) - 2) < DBL_EPSILON);
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
	(ALFID_T &)responseZero.timeDelta = htonl(LAST_WELL_KNOWN_ALFID); 
	EvaluateCookie(responseZero, t1, & nearEnd);

	responseZero.timeDelta = htonl((u_long)(t1 - t0)); 
	responseZero.cookie ^= ((UINT64)request.salt << 32) | request.salt;
	responseZero.hs.Set<FSP_Challenge, ACK_INIT_CONNECT>();

	affirmedRequest.cookie = responseZero.cookie ^ (((UINT64)request.salt << 32) | request.salt);
	affirmedRequest.initCheckCode = request.initCheckCode;
	affirmedRequest.idALF = htonl(LAST_WELL_KNOWN_ALFID);
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

	int32_t r = 1;
	r = get32BE(&r);
	memset(&nearEnd, 0, sizeof(nearEnd));
	request.timeStamp = htonll(t0);
	// initCheckCode, salt should be random, but remain as-is for test purpose
	request.hs.Set<FSP_InitiateRequest, INIT_CONNECT>();

	timestamp_t t1 = NowUTC();
	struct _CookieMaterial cm;
	cm.idALF = nearEnd.u.idALF;
	cm.idListener = htonl(LAST_WELL_KNOWN_ALFID);
	// the cookie depends on the listening session ID AND the responding session ID
	cm.salt = request.salt;
	responseZero.initCheckCode = request.initCheckCode;
	responseZero.cookie = CalculateCookie((BYTE *) & cm, sizeof(cm), t1);
	responseZero.timeDelta = htonl((u_long)(t1 - t0)); 
	responseZero.cookie ^= ((UINT64)request.salt << 32) | request.salt;
	responseZero.hs.Set<FSP_Challenge, ACK_INIT_CONNECT>();

	acknowledgement.expectedSN = 1;
	acknowledgement.sequenceNo = 1;
	acknowledgement.integrity.id.peer = htonl(LAST_WELL_KNOWN_ALFID); 
	acknowledgement.integrity.id.source = nearEnd.u.idALF;

	// should the connect parameter header. but it doesn't matter
	acknowledgement.hs.Set<FSP_AckConnectRequest, ACK_CONNECT_REQ>();

	PairALFID savedId = acknowledgement.integrity.id;
	CSocketItemExDbg socket;
	socket.ResetVMAC();

	socket.SetIntegrityCheckCodeP1(& acknowledgement);

	UINT64 savedICC = acknowledgement.integrity.code;
	acknowledgement.integrity.id = savedId;
	socket.SetIntegrityCheckCodeP1(& acknowledgement);
	Assert::AreEqual<UINT64>(savedICC, acknowledgement.integrity.code);

	BYTE ackbuf[sizeof(acknowledgement) + 5];
	// suppose a misalignment found..
	memcpy(ackbuf + 3, & acknowledgement, sizeof(acknowledgement));
	FSP_AckConnectRequest & ack2 = *(FSP_AckConnectRequest *)(ackbuf + 3);

	ack2.integrity.id = savedId;
	socket.SetIntegrityCheckCodeP1(& ack2);
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



void UnitTestTestSetFlag()
{
	static ControlBlock::FSP_SocketBuf buf;
	buf.SetFlag<IS_COMPLETED>();
	Assert::IsTrue(buf.flags == 1 << IS_COMPLETED);
}


void UnitTestGenerateSNACK()
{
	static const ControlBlock::seq_t FIRST_SN = 12;
	static const int MAX_GAPS_NUM = 2;
	static const int MAX_BLOCK_NUM = 0x20000;	// 65536 * 2

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
	Assert::IsTrue(r == 1 && seq0 == FIRST_SN + 3);

	// when a very large gap among small continuous data segments found
	skb1 = socket.AllocRecvBuf(FIRST_SN + 0x10003);
	skb1->SetFlag<IS_FULFILLED>();
	Assert::IsNotNull(skb1);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 0x10004);

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 1 && seq0 == FIRST_SN + 3);

	// when gap descriptors overflow
	skb1 = socket.AllocRecvBuf(FIRST_SN + 0x8003);
	skb1->SetFlag<IS_FULFILLED>();
	Assert::IsNotNull(skb1);
	Assert::IsTrue(pSCB->recvWindowNextSN == FIRST_SN + 0x10004);

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 2 && seq0 == FIRST_SN + 0x8004);

	// when a very large continuous data segment among small gaps
	for(int i = 4; i < 0x10003; i++)
	{
		skb1 = socket.AllocRecvBuf(FIRST_SN + i);
		Assert::IsNotNull(skb1);
		skb1->SetFlag<IS_FULFILLED>();
	}

	r = pSCB->GetSelectiveNACK(seq0, gaps, MAX_GAPS_NUM);
	Assert::IsTrue(r == 1 && seq0 == FIRST_SN + 3);

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

	pSCB->welcomedNextSNtoSend = pSCB->sendWindowFirstSN = FIRST_SN;
	pSCB->sendBufferNextSN = pSCB->sendWindowNextSN = FIRST_SN + 1;
	// Pretend that the first packet has been sent and is waiting acknowledgement...
	// A NULL acknowledgement, Keep-Alive
	int r = socket.RespondSNACK(FIRST_SN + 1, NULL, 0);
	Assert::IsTrue(r == 0 && pSCB->sendBufferNextSN == pSCB->sendWindowFirstSN);
	Assert::IsTrue(pSCB->sendWindowFirstSN == FIRST_SN + 1);
	Assert::IsTrue(pSCB->sendWindowNextSN == FIRST_SN + 1);


	pSCB->SetSendWindowWithHeadReserved(FIRST_SN);
	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadSend();
	Assert::IsNotNull(skb);
	Assert::IsTrue(pSCB->sendWindowSize == 1);	// set by GetVeryFirstSendBuf
	Assert::IsTrue(pSCB->sendBufferNextSN == FIRST_SN + 1);
	skb->SetFlag<IS_COMPLETED>();
	skb->Lock();

	skb = pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	skb->Lock();
	pSCB->GetSendBuf();
	skb->SetFlag<IS_COMPLETED>();
	skb->Lock();
	Assert::IsTrue(pSCB->sendBufferNextSN == FIRST_SN + 3);

	// emulate sending, together with setting skb->timeOut
	// assume 3 packets sent
	pSCB->sendWindowNextSN += 3;
	pSCB->sendWindowSize = MAX_BLOCK_NUM;	// don't let size of send window limit the test
	Assert::IsTrue(pSCB->sendWindowNextSN == FIRST_SN + 3);

	// acknowledge the first two
	r = socket.RespondSNACK(FIRST_SN + 2, NULL, 0);
	Assert::IsTrue(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 2);
	Assert::IsTrue(pSCB->CountUnacknowledged() >= 0);
	Assert::IsTrue(pSCB->sendWindowSize == MAX_BLOCK_NUM - 2);

	// Now, more test...
	for(int i = 3; i < MAX_BLOCK_NUM; i++)
	{
		skb = pSCB->GetSendBuf();
		Assert::IsTrue(skb != NULL);
		skb->SetFlag<IS_COMPLETED>();
		skb->Lock();
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
	Assert::IsTrue(pSCB->CountUnacknowledged() >= 0);
	// again, an outdated one
	r = socket.RespondSNACK(FIRST_SN + 2, gaps, 1);
	Assert::IsTrue(r == -EDOM && pSCB->sendWindowFirstSN == FIRST_SN + 2);
	Assert::IsTrue(pSCB->CountUnacknowledged() >= 0);

	// this is a legal one
	r = socket.RespondSNACK(FIRST_SN + 5, gaps, 1);
	Assert::IsTrue(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 3);
	Assert::IsTrue(pSCB->CountUnacknowledged() >= 0);

	// this is a legal but redundant two gaps
	gaps[1].dataLength = 1;
	gaps[1].gapWidth = 1;
	r = socket.RespondSNACK(FIRST_SN + 5, gaps, 2);
	Assert::IsTrue(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 3);
	Assert::IsTrue(pSCB->CountUnacknowledged() >= 0);

	// two gaps, overlap with previous one [only to urge retransmission of those negatively acknowledged]
	r = socket.RespondSNACK(FIRST_SN + 7, gaps, 2);
	Assert::IsTrue(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 3);
	Assert::IsTrue(pSCB->CountUnacknowledged() >= 0);

	// two gaps, do real new acknowledgement
	r = socket.RespondSNACK(FIRST_SN + 9, gaps, 2);
	Assert::IsTrue(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 5);
	Assert::IsTrue(pSCB->CountUnacknowledged() >= 0);

	// a very large continuous data segment is acknowledged
	r = socket.RespondSNACK(FIRST_SN + 0x1000A, gaps, 2);
	Assert::IsTrue(r == 0 && pSCB->sendWindowFirstSN == FIRST_SN + 0x10006);
	Assert::IsTrue(pSCB->sendWindowSize == MAX_BLOCK_NUM - 0x10006);
	Assert::IsTrue(pSCB->CountUnacknowledged() >= 0);

	// Test round-robin...
	for(int i = MAX_BLOCK_NUM + 2; i < MAX_BLOCK_NUM + 0x10000; i++)
	{
		skb = pSCB->GetSendBuf();
		Assert::IsTrue(skb != NULL);
		skb->SetFlag<IS_COMPLETED>();
		skb->Lock();
	}
	pSCB->sendWindowNextSN += 0x10000;	// queuing to send is not the same as sending

	// an even larger continuous data segment is acknowledged
	r = socket.RespondSNACK(FIRST_SN + MAX_BLOCK_NUM + 0xF000, gaps, 2);
	Assert::IsTrue(r == 0 && pSCB->sendWindowHeadPos == 0xEFFC);
	Assert::IsTrue(pSCB->sendWindowSize == - 0xEFFC);	// overflow, but don't care!
	Assert::IsTrue(pSCB->sendWindowFirstSN == FIRST_SN + MAX_BLOCK_NUM + 0xEFFC);
	Assert::IsTrue(pSCB->CountUnacknowledged() >= 0);

	// TODO: Test calculation of RTT and Keep alive timeout 
}



void UnitTestSocketInState()
{
	CSocketItemExDbg socket(2, 2);
	socket.SetState(QUASI_ACTIVE);
	bool r = socket.InStates(3, COMMITTING, RESUMING, QUASI_ACTIVE);
	Assert::IsTrue(r);
	socket.SetState(CLOSABLE);
	r = socket.InStates(4, COMMITTING2, RESUMING, QUASI_ACTIVE, CLOSED);
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
	ALFID_T id = (CLowerInterface::Singleton())->RandALFID();
	Assert::IsFalse(id == 0, L"There should be free id space");

	id = (CLowerInterface::Singleton())->RandALFID(addrList);
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
	PktBufferBlock *CurrentHead() { return freeBufferHead; }
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
	CSocketItemExDbg socket(2, 2);

	lowerSrv.InitBuffer();	// initialize the chained list of the free blocks

	PktBufferBlock *p0 = lowerSrv.GetBuffer();
	PktBufferBlock *p = p0;
	for(int i = 0; i < MAX_BUFFER_BLOCKS; i++)
	{
		Assert::IsTrue(p != NULL);
		p = lowerSrv.GetBuffer();
	}
	Assert::IsTrue(p == NULL);
	//
	memset(& socket, 0, sizeof(CSocketItemExDbg));

	socket.PushPacketBuffer(p0);

	// Peek...return the header packet descriptor itself
	FSP_NormalPacketHeader *hdr = socket.PeekLockPacketBuffer();
	Assert::IsNotNull(hdr);
	socket.PopUnlockPacketBuffer();

	// So, p0 has been freed
	p = p0;
	for(int i = 0; i < MAX_BUFFER_BLOCKS - 1; i++)
	{
		Assert::IsTrue(p == lowerSrv.CurrentHead());	// what? needs it been asserted?
		p++;
		lowerSrv.FreeBuffer(p);
	}
}



void UnitTestConnectQueue()
{
	static ConnectRequestQueue commandRequests;
	CommandToLLS raw;
	raw.opCode = InitConnection;
	CommandNewSessionSrv t(&raw);

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


// TODO...
static void pbuf(void *p, int len, char *s)
{
	int i;
	if (s)
		printf("%s", s);
	for (i = 0; i < len; i++)
		printf("%02x", ((unsigned char *)p)[i]);
	printf("\n");
}



void UnitTestVMAC_AE()
{
	vmac_ae_ctx_t *ctx;
	uint64_t tagh, tagh2, tagl, tagl2;
	void *p;
	unsigned char *m, *ct, *pt;
	unsigned char key[] = "abcdefghijklmnop";
	unsigned char nonce[] = "bcdefghi\0\0\0\0\0\0\0\0";
	unsigned int  vector_lengths[] = {0, 3, 48, 300, 3000000};
	#if (VMAC_TAG_LEN == 64)
	char *should_be[] = {"4EDE4AE94EDD87E1","3E4DA5C2AAD72DD9",
	                     "386A3E7B2867701B","48827AB2ABA0191D",
	                     "400563BE24C6B88A"};
	#else
	char *should_be[] = {"E87569084EFF3E1CCA1500C5A6A89CE6",
	                     "BE94EE5EF0B907A0917BCB8FE772AB08",
	                     "DF371629033248692F31ABA01270DC05",
	                     "17C9B2477A6B256F5B80B40292BE0E34",
	                     "B9CCCE965D131DEF578CAC1CA56476B6"};
	#endif
	unsigned speed_lengths[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
	unsigned speed_iters[] = {1<<22, 1<<21, 1<<20, 1<<19, 1<<18,
	                               1<<17, 1<<16, 1<<15, 1<<14};
	unsigned int i, j;
    clock_t ticks;
    double cpb;
	const unsigned int buf_len = 3 * (1 << 20);
	
	/* Initialize context and message buffer, all 16-byte aligned */
	p = malloc(sizeof(vmac_ae_ctx_t) + 16);
	ctx = (vmac_ae_ctx_t *)(((size_t)p + 16) & ~((size_t)15));
	p = malloc(buf_len + 32);
	m = (unsigned char *)(((size_t)p + 16) & ~((size_t)15));
	p = malloc(buf_len + 32);
	ct = (unsigned char *)(((size_t)p + 16) & ~((size_t)15));
	p = malloc(buf_len + 32);
	pt = (unsigned char *)(((size_t)p + 16) & ~((size_t)15));
	/* memset(m, 0, buf_len + 16); */
	vmac_ae_set_key(key, ctx);
	vmac_ae_reset(ctx);
	
	/* Generate vectors */
	for (i = 0; i < sizeof(vector_lengths)/sizeof(unsigned int); i++) {
		for (j = 0; j < vector_lengths[i]; j++)
			m[j] = (unsigned char)('a'+j%3);
		vmac_ae_header(m, vector_lengths[i], ctx);
		vmac_ae_encrypt(m, ct, vector_lengths[i], nonce, 8, ctx);
		vmac_ae_footer(m, vector_lengths[i], ctx);
		tagh = vmac_ae_finalize(&tagl, ctx);
		vmac_ae_header(m, vector_lengths[i], ctx);
		vmac_ae_decrypt(ct, pt, vector_lengths[i], nonce, 8, ctx);
		vmac_ae_footer(m, vector_lengths[i], ctx);
		tagh2 = vmac_ae_finalize(&tagl2, ctx);
		#if (VMAC_TAG_LEN == 64)
		printf("\'abc\' * %7u: %016llX Should be: %s\n",
		      vector_lengths[i]/3,tagh,should_be[i]);
		printf("Encrypt/decrypt %s, tags %s\n",
		      (memcmp(pt, m, vector_lengths[i])  ? "mismatch" : "match"),
		      (tagh == tagh2 ? "match" : "mismatch"));
		#else
		printf("\'abc\' * %7u: %016llX%016llX\nShould be      : %s\n",
		      vector_lengths[i]/3,tagh,tagl,should_be[i]);
		printf("Encrypt/decrypt %s, tags %s\n",
		      (memcmp(pt, m, vector_lengths[i])  ? "mismatch" : "match"),
		      ((tagh == tagh2) && (tagl == tagl2) ? "match" : "mismatch"));
		#endif
	}
	
	/* Speed test */
#if 1
#define VMAC_HZ  2e9	// 2Ghz
	for (i = 0; i < sizeof(speed_lengths)/sizeof(unsigned int); i++) {
		ticks = clock();
		for (j = 0; j < speed_iters[i]; j++) {
			vmac_ae_encrypt(m, ct, speed_lengths[i], nonce, 8, ctx);
			tagh = vmac_ae_finalize(&tagl, ctx);
			nonce[7]++;
		}
		ticks = clock() - ticks;
		cpb = ((ticks*VMAC_HZ)/
		      ((double)CLOCKS_PER_SEC*speed_lengths[i]*speed_iters[i]));
		printf("%4u bytes, %2.2f cpb\n", speed_lengths[i], cpb);
	}
#endif
}

namespace UnitTestFSP
{		
	TEST_CLASS(UnitTest1)
	{
	public:
		TEST_METHOD(TestOpCodeStateNoticeStringizer)
		{
			UnitTestOpCodeStateNoticeNames();
		}

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

		TEST_METHOD(TestCubicRoot)
		{
			UnitTestCubicRoot();
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


		TEST_METHOD(TestVMAC_AE)
		{
#if 0
			// as VMAC_AE failed unit test we remove VMAC support
			UnitTestVMAC_AE();
#endif
		}


		TEST_METHOD(TestQuasibitfield)
		{
			UnitTestQuasibitfield();
		}


		TEST_METHOD(TestTestSetFlag)
		{
			UnitTestTestSetFlag();
		}


		TEST_METHOD(TestSocketSrvTLB)
		{
			UnitTestSocketSrvTLB();
		}


		TEST_METHOD(TestConnectQueue)
		{
			UnitTestConnectQueue();
		}


		TEST_METHOD(TestReceiveQueue)
		{
			UnitTestReceiveQueue();
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
