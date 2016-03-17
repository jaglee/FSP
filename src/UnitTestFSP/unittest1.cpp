#include "targetver.h"

#include "FSP_TestClass.h"

// Headers for CppUnitTest
#define _ALLOW_KEYWORD_MACROS
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

// 
void UnitTestGenerateSNACK();
void UnitTestSendRecvWnd();
void UnitTestHasBeenCommitted();

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


void UnitTestBackLogs()
{
	static const int MAX_BACKLOG_SIZE = 4;
	static const int TEST_SIZE = sizeof(ControlBlock) + sizeof(BackLogItem) * MAX_BACKLOG_SIZE;
	ControlBlock *buf = (ControlBlock *)_alloca(TEST_SIZE);
	ControlBlock & cqq = *buf;
	BackLogItem item, *pItem;
	register int i;
	int n;

	cqq.Init(MAX_BACKLOG_SIZE);
	pItem = cqq.backLog.Peek();
	Assert::IsNull(pItem, L"There should be no item to be popped");

	item.idRemote = 1234;
	item.salt = 4321;	// item.sessionKey[0] = 0xAA; // used to exploit session key
	for(i = 0; i < MAX_BACKLOG_SIZE; i++)
	{
		n = cqq.backLog.Put(& item);
		//
		sprintf_s(linebuf, sizeof(linebuf), "Insert at position %d\n", n);
		Logger::WriteMessage(linebuf);
	}
	n = cqq.backLog.Put(& item);
	Assert::IsTrue(n < 0, L"Cannot push into backlog when overflow");
	
	bool b = cqq.backLog.Has(& item);
	Assert::IsTrue(b, L"Cannot find the backlog item just put into the queue");

	item.salt = 3412;	// item.sessionKey[0] = 0xBB; // used to exploit session key
	b = cqq.backLog.Has(& item);
	Assert::IsFalse(b, L"Nonexistent backlog item should not be found");

	for(i = 0; i < MAX_BACKLOG_SIZE; i++)
	{
		pItem = cqq.backLog.Peek();
		Assert::IsNotNull(pItem, L"There should be log item peekable");
		n = cqq.backLog.Pop();
		sprintf_s(linebuf, sizeof(linebuf), "Position at %d popped\n", n);
		Logger::WriteMessage(linebuf);
	}
	pItem = cqq.backLog.Peek();
	Assert::IsNull(pItem, L"Cannot peek anothing when it is empty");
	n = cqq.backLog.Pop();
	Assert::IsTrue(n < 0, L"Cannot pop when it is empty");
	//
	// change the length of the backlog queue on the fly
	//
	cqq.Init(MIN_QUEUED_INTR);
	pItem = cqq.backLog.Peek();
	Assert::IsNull(pItem, L"There should be no item peekable");

	item.idRemote = 1234;
	item.salt = 4321;	// item.sessionKey[0] = 0xAA; // used to exploit session key
	for(i = 0; i < MIN_QUEUED_INTR; i++)
	{
		n = cqq.backLog.Put(& item);
		//
		sprintf_s(linebuf, sizeof(linebuf), "Insert at position %d\n", n);
		Logger::WriteMessage(linebuf);
	}
	n = cqq.backLog.Put(& item);
	Assert::IsTrue(n < 0, L"Cannot push into backlog when overflow");
	
	b = cqq.backLog.Has(& item);
	Assert::IsTrue(b, L"Cannot find the backlog item just put into the queue");

	item.salt = 3412;	// item.sessionKey[0] = 0xBB; // used to exploit session key
	b = cqq.backLog.Has(& item);
	Assert::IsFalse(b, L"Nonexistent backlog item should not be found");

	for(i = 0; i < MIN_QUEUED_INTR; i++)
	{
		pItem = cqq.backLog.Peek();
		Assert::IsNotNull(pItem, L"There should be log item peekable");
		n = cqq.backLog.Pop();
		sprintf_s(linebuf, sizeof(linebuf), "Position at %d popped\n", n);
		Logger::WriteMessage(linebuf);
	}
	pItem = cqq.backLog.Peek();
	Assert::IsNull(pItem, L"Cannot peek anothing when it is empty");
	n = cqq.backLog.Pop();
	Assert::IsTrue(n < 0, L"Cannot pop when it is empty");
}



void UnitTestNoticeQ()
{
	ControlBlock *buf = (ControlBlock *)_alloca(sizeof(ControlBlock));
	ControlBlock & cqq = *buf;
	int r;

	memset(buf, 0, sizeof(ControlBlock));

	FSP_ServiceCode c = cqq.notices.Pop();
	Assert::IsTrue(c == NullCommand, L"Nothing should be popped out from an empty queue");

	r = cqq.notices.Put(FSP_NotifyTimeout);		// 1
	Assert::IsTrue(r == 0, L"FSP_NotifyTimeout should have been put on an empty queue");

	r = cqq.notices.Put(FSP_NotifyReset);		// 2
	Assert::IsTrue(r == 1, L"FSP_NotifyReset should have been put on an un-fulfilled queue");

	r = cqq.notices.Put(FSP_NotifyDataReady);	// 3
	Assert::IsTrue(r == 2, L"FSP_NotifyDataReady should have been put on an un-fulfilled queue");

	r = cqq.notices.Put(FSP_NotifyDataReady);
	Assert::IsTrue(r == FSP_MAX_NUM_NOTICE, L"Duplicated FSP_NotifyDataReady should be put on queue merged");

	r = cqq.notices.Put(FSP_NotifyReset);		// 4, no, it cannot be merged with previous, uncontinuous duplicate notification
	Assert::IsTrue(r == 3, L"FSP_NotifyReset should be put on an un-fulfilled queue");

	r = cqq.notices.Put(FSP_NotifyRecycled);		// 5
	Assert::IsTrue(r == 4, L"FSP_NotifyRecycled should have been put on an un-fulfilled queue");

	r = cqq.notices.Put(FSP_NotifyAccepted);		// 6
	Assert::IsTrue(r == 5, L"FSP_NotifyAccepted should have been put on an un-fulfilled queue");

	r = cqq.notices.Put(FSP_NotifyFlushed);		// 7
	Assert::IsTrue(r == 6, L"FSP_NotifyFlushed should have been put on an un-fulfilled queue");

	r = cqq.notices.Put(FSP_NotifyBufferReady);	// 8
	Assert::IsTrue(r == 7, L"FSP_NotifyBufferReady should have been put on an un-fulfilled queue");

	r = cqq.notices.Put(FSP_NotifyTimeout);	// 9, no, it cannot be merged with previous, uncontinuous duplicate notification
	Assert::IsTrue(r == 8, L"FSP_NotifyTimeout should be put on an un-fulfilled queue");

	r = cqq.notices.Put(FSP_IPC_CannotReturn);		// 10
	Assert::IsTrue(r == 9, L"FSP_IPC_CannotReturn should have been put on an un-fulfilled queue");

	////the queue is too large to raise such an error
	//r = cqq.notices.Put(FSP_NotifyOverflow);
	//Assert::IsTrue(r < 0, L"FSP_NotifyOverflow should have failed to be put on a fulfilled queue");
	//r = cqq.notices.Put(FSP_NotifyNameResolutionFailed);
	//Assert::IsFalse(r < 0, L"FSP_NotifyNameResolutionFailed should have failed to be put on a fulfilled queue");

	// 
	c = cqq.notices.Pop();	// 1
	Assert::IsTrue(c == FSP_NotifyTimeout, L"What is popped should be what was pushed 1st");

	c = cqq.notices.Pop();	// 2
	Assert::IsTrue(c == FSP_NotifyReset, L"What is popped should be what was pushed 2nd");

	c = cqq.notices.Pop();	// 3
	Assert::IsTrue(c == FSP_NotifyDataReady, L"What is popped should be what was pushed 3rd");

	c = cqq.notices.Pop();	// 4
	Assert::IsTrue(c == FSP_NotifyReset, L"What is popped should be what was pushed 4th");

	c = cqq.notices.Pop();	// 5
	Assert::IsTrue(c == FSP_NotifyRecycled, L"What is popped should be what was pushed 5th");

	c = cqq.notices.Pop();	// 6
	Assert::IsTrue(c == FSP_NotifyAccepted, L"What is popped should be what was pushed 6th");

	c = cqq.notices.Pop();	// 7
	Assert::IsTrue(c == FSP_NotifyFlushed, L"What is popped should be what was pushed 7th");

	c = cqq.notices.Pop();	// 8
	Assert::IsTrue(c == FSP_NotifyBufferReady, L"What is popped should be what was pushed 8th");

	c = cqq.notices.Pop();	// 9
	Assert::IsTrue(c == FSP_NotifyTimeout, L"What is popped should be what was pushed 9th");

	c = cqq.notices.Pop();	// 10
	Assert::IsTrue(c == FSP_IPC_CannotReturn, L"What is popped should be what was pushed 10th");

	c = cqq.notices.Pop();
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



// 'Big' int division, see also CSocketItemEx::RespondToSNACK@timers.cpp
int32_t CalculateLargestOffset(uint64_t tdiff64_us, uint64_t rtt64_us, uint32_t tRoundTrip_us, int32_t sentWidth)
{
	// Source code embedded, copied and pasted here; declaration of largestOffset moved to top
	register uint32_t	largestOffset = -1;
	int64_t		rtt_delta = int64_t(rtt64_us - ((uint64_t)tRoundTrip_us << 1));
	if(rtt_delta <= 0)
		goto l_retransmitted;

	if(int64_t(rtt_delta - tdiff64_us) >= 0)
	{
		largestOffset = sentWidth;
		// if the unsigned tdiff64_us == 0, it falled into this category
	}
	else
	{
		// partially unrolled loop
		uint64_t hiqword = (rtt_delta >> 32) * sentWidth;	// The initial remainder, actually;
		uint32_t lodword = ((rtt_delta & 0xFFFFFFFF) * sentWidth) & 0xFFFFFFFF;
		hiqword += ((rtt_delta & 0xFFFFFFFF) * sentWidth) >> 32;
		// We are sure 31st bit of sendWidth is 0 thus 63rd bit of hiqword is 0
		largestOffset = 0;
		for(register int i = 31; i >= 0; i--)
		{
			hiqword <<= 1;
			hiqword |= BitTest((LONG *) & lodword, i);
			if(hiqword >= tdiff64_us)
			{
				hiqword -= tdiff64_us;
				BitTestAndSet((LONG *) & largestOffset, i);
			}
		}
		//
		if(largestOffset == 0)
			goto l_retransmitted;
	}
	// suffix code added here
l_retransmitted:
	return largestOffset;
}



void UnitTestBIDivision()
{
	int32_t r = CalculateLargestOffset(0, 0, 0, 5);
	Assert::IsTrue(r == -1);	// because rtt_delta = 0
	// lastest sent time - earlist sent time  = 2us
	// this RTT instance: 5us
	// Round trip time: 1us
	r =  CalculateLargestOffset(2, 5, 1, 5);
	Assert::IsTrue(r == 5);
	// lastest sent time - earlist sent time  = 5us
	// this RTT instance: 4us
	// Round trip time: 1us
	r =  CalculateLargestOffset(5, 4, 1, 5);
	Assert::IsTrue(r == 2);
	//
	// lastest sent time - earlist sent time  = 0x5,0000,0000us
	// this RTT instance: 0x4,0000,0000us
	// Round trip time: 0x8000,0000us
	r =  CalculateLargestOffset( 0x500000000LL, 0x400000000LL, 0x80000000, 5);
	Assert::IsTrue(r == 3);
}



void UnitTestGCM_AES()
{
	BYTE samplekey[16] = { 0, 0xB1, 0xC2, 3, 4, 5, 6, 7, 8, 0xD9, 10, 11, 12, 13, 14, 15 };
	ALIGN(MAC_ALIGNMENT) BYTE payload[80];
	GCM_AES_CTX ctx;
	uint64_t IV = 1;
	BYTE tag[8];

	memset(payload, 0, sizeof(payload));

	GCM_AES_SetKey(& ctx, samplekey, sizeof(samplekey));

	GCM_AES_AuthenticatedEncrypt(& ctx, IV, NULL, 0, (uint64_t *)payload, 12, NULL, tag, sizeof(tag));
	int r = GCM_AES_AuthenticateAndDecrypt(& ctx, IV, NULL, 0, (uint64_t *)payload, 12, tag, sizeof(tag), NULL); 
	Assert::IsTrue(r == 0);

	for(register int i = 0; i < sizeof(payload); i++)
	{
		payload[i] = (BYTE )i;
	}

	GCM_AES_AuthenticatedEncrypt(& ctx, IV, NULL, 0, (uint64_t *)payload, 31, NULL, tag, sizeof(tag));
	r = GCM_AES_AuthenticateAndDecrypt(& ctx, IV, NULL, 0, (uint64_t *)payload, 31, tag, sizeof(tag), NULL); 
	Assert::IsTrue(r == 0);

	GCM_AES_AuthenticatedEncrypt(& ctx, IV, payload + 32, 17, (uint64_t *)payload, 31, (uint64_t *)payload + 4, tag, sizeof(tag));
	r = GCM_AES_AuthenticateAndDecrypt(& ctx, IV, payload + 32, 17, (uint64_t *)payload, 31, tag, sizeof(tag), (uint64_t *)payload + 4); 
	Assert::IsTrue(r == 0);

	for(register int i = 0; i < sizeof(payload); i++)
	{
		Assert::IsTrue(payload[i] == i);
	}

	for(register int i = 0; i < 17; i++)
	{
		payload[i] ^= 0xFF;
	}

	GCM_AES_AuthenticatedEncrypt(& ctx, IV, payload + 32, 17, (uint64_t *)payload, 31, (uint64_t *)payload + 4, tag, sizeof(tag));
	for(register int i = 0; i < sizeof(payload); i++)
	{
		sprintf_s(linebuf, sizeof(linebuf), "%d ", payload[i]);
		Logger::WriteMessage(linebuf);
	}
	sprintf_s(linebuf, sizeof(linebuf), "\n");
	Logger::WriteMessage(linebuf);

	r = GCM_AES_AuthenticateAndDecrypt(& ctx, IV, payload + 32, 17, (uint64_t *)payload, 31, tag, sizeof(tag), (uint64_t *)payload + 4); 
	Assert::IsTrue(r == 0);

	for(register int i = 17; i < sizeof(payload); i++)
	{
		Assert::IsTrue(payload[i] == i);
	}
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
	Assert::AreEqual<int>(acknowledgement.GetFlag<Compressed>(), 2);
	//
	acknowledgement.ClearFlag<ToBeContinued>();
	Assert::IsTrue(acknowledgement.flags_ws[3] == 2);
	acknowledgement.ClearFlag<Compressed>();
	Assert::IsTrue(acknowledgement.flags_ws[3] == 0);
}



void UnitTestTestSetFlag()
{
	static ControlBlock::FSP_SocketBuf buf;
	buf.SetFlag<IS_COMPLETED>();
	Assert::IsTrue(buf.flags == 1 << IS_COMPLETED);
}



void UnitTestSocketInState()
{
	CSocketItemExDbg socket(2, 2);
	socket.SetState(CLONING);
	bool r = socket.InStates(3, COMMITTING, CLONING, PRE_CLOSED);
	Assert::IsTrue(r);
	socket.SetState(CLOSABLE);
	r = socket.InStates(4, COMMITTING2, CLONING, PRE_CLOSED, CLOSED);
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



void UnitTestOCB_MAC()
{
#if 0	// due to patent issue OCB mode is just a comparable
	FSP_InitiateRequest request;
	FSP_Challenge responseZero;	// zero hint no state
	FSP_AckConnectRequest acknowledgement;
	CtrlMsgHdr nearEnd;
	timestamp_t t0 = NowUTC();

	int32_t r = 1;
	r = htobe32(r);
	memset(&nearEnd, 0, sizeof(nearEnd));
	request.timeStamp = htobe64(t0);
	// initCheckCode, salt should be random, but remain as-is for test purpose
	request.hs.Set<FSP_InitiateRequest, INIT_CONNECT>();

	timestamp_t t1 = NowUTC();
	struct _CookieMaterial cm;
	cm.idALF = nearEnd.u.idALF;
	cm.idListener = htobe32(LAST_WELL_KNOWN_ALFID);
	// the cookie depends on the listening session ID AND the responding session ID
	cm.salt = request.salt;
	responseZero.initCheckCode = request.initCheckCode;
	responseZero.cookie = CalculateCookie((BYTE *) & cm, sizeof(cm), t1);
	responseZero.timeDelta = htobe32((u_long)(t1 - t0)); 
	responseZero.cookie ^= ((uint64_t)request.salt << 32) | request.salt;
	responseZero.hs.Set<FSP_Challenge, ACK_INIT_CONNECT>();

	acknowledgement.expectedSN = 1;
	acknowledgement.sequenceNo = 1;
	// should the connect parameter header. but it doesn't matter
	acknowledgement.hs.Set<FSP_AckConnectRequest, ACK_CONNECT_REQ>();

	BYTE samplekey[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	CSocketItemExDbg socket;
	socket.SetPairOfFiberID(nearEnd.u.idALF, htobe32(LAST_WELL_KNOWN_ALFID));

	socket.InstallSessionKey(samplekey);
	socket.SetIntegrityCheckCode(& acknowledgement);

	// ValidateICC validates the received packet, the source and sink ID should be exchanged for the receiver
	socket.SetPairOfFiberID(htobe32(LAST_WELL_KNOWN_ALFID), nearEnd.u.idALF);

	bool checked = socket.ValidateICC(& acknowledgement);
	Assert::IsTrue(checked);

	socket.SetIntegrityCheckCode(& acknowledgement, 9);	// arbitrary length in the stack

	socket.SetPairOfFiberID(nearEnd.u.idALF, htobe32(LAST_WELL_KNOWN_ALFID));
	checked = socket.ValidateICC(& acknowledgement, 9);
	Assert::IsTrue(checked);
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

		TEST_METHOD(TestBigIntDivision)
		{
			UnitTestBIDivision();
		}

		TEST_METHOD(TestGCM_AES)
		{
			UnitTestGCM_AES();
		}

		TEST_METHOD(TestOCB_MAC)
		{
			UnitTestOCB_MAC();
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

		TEST_METHOD(TestGenerateSNACK)
		{
			UnitTestGenerateSNACK();
		}


		TEST_METHOD(TestSendRecvWnd)
		{
			UnitTestSendRecvWnd();
		}


		TEST_METHOD(TestHasBeenCommitted)
		{
			UnitTestHasBeenCommitted();
		}


		TEST_METHOD(TestSocketInState)
		{
			UnitTestSocketInState();
		}
	};
}
