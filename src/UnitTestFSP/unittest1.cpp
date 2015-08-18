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
	b = cqq.SetReturned((uint32_t)n, (FSPIPC::SRVNotice)2);
	Assert::IsTrue(b);
	b = cqq.Fetch((uint32_t)n, & r);
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
	b = cqq.SetReturned((uint32_t)n, (FSPIPC::SRVNotice)3);
	Assert::IsTrue(b);

	b = cqq.Fetch((uint32_t)n, & r);
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





void UnitTestVMAC()
{
#if 0
	// as VMAC_AE failed unit test we remove VMAC support
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
	acknowledgement.integrity.id.peer = htobe32(LAST_WELL_KNOWN_ALFID); 
	acknowledgement.integrity.id.source = nearEnd.u.idALF;

	// should the connect parameter header. but it doesn't matter
	acknowledgement.hs.Set<FSP_AckConnectRequest, ACK_CONNECT_REQ>();

	PairALFID savedId = acknowledgement.integrity.id;
	CSocketItemExDbg socket;
	socket.ResetVMAC();

	socket.SetIntegrityCheckCodeP1(& acknowledgement);

	uint64_t savedICC = acknowledgement.integrity.code;
	acknowledgement.integrity.id = savedId;
	socket.SetIntegrityCheckCodeP1(& acknowledgement);
	Assert::AreEqual<uint64_t>(savedICC, acknowledgement.integrity.code);

	BYTE ackbuf[sizeof(acknowledgement) + 5];
	// suppose a misalignment found..
	memcpy(ackbuf + 3, & acknowledgement, sizeof(acknowledgement));
	FSP_AckConnectRequest & ack2 = *(FSP_AckConnectRequest *)(ackbuf + 3);

	ack2.integrity.id = savedId;
	socket.SetIntegrityCheckCodeP1(& ack2);
	Assert::AreEqual<uint64_t>(savedICC, ack2.integrity.code);
#endif
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
	// FSP_Header_Manager(void *p1, int len);
	// template<typename THdr> uint16_t PushExtHeader(THdr *pExtHdr)
	// void PushDataBlock(BYTE *buf, int len)
	//
	// FSP_Header_Manager(void *p1);
	// template<typename THdr>	THdr * PopExtHeader()
	// void * TopAsDataBlock() const { return pHdr + pStackPointer; }
	// int	NextHeaderOffset() const { return (int)pStackPointer; }
}



void UnitTestVMAC_AE()
{
#if 0
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
#endif
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




void UnitTestPersistConnect()
{
	int memsize = sizeof(ControlBlock) + (sizeof ControlBlock::FSP_SocketBuf + MAX_BLOCK_SIZE) * 8;
	const ControlBlock::seq_t FIRST_SN = 12;

	CSocketItemExDbg socket;
	ControlBlockDbg *pSCB = socket.GetControlBlock();
	pSCB->Init((memsize - sizeof(ControlBlock))/ 2, (memsize - sizeof(ControlBlock)) / 2);

	pSCB->SetRecvWindowHead(FIRST_SN);
	pSCB->SetSendWindowHead(FIRST_SN);

	socket.PersistConnect();
	ControlBlock::PFSP_SocketBuf skb = pSCB->GetSendQueueHead();
	Assert::IsTrue(skb->opCode == PERSIST && pSCB->CountSendBuffered() == 1);

	// PersistConnect is itempotent
	socket.PersistConnect();
	skb = pSCB->GetSendQueueHead();
	Assert::IsTrue(skb->opCode == PERSIST && pSCB->CountSendBuffered() == 1);

	skb->opCode = PURE_DATA;
	socket.PersistConnect();
	skb = pSCB->GetSendQueueHead();
	Assert::IsTrue(skb->opCode == PERSIST && pSCB->CountSendBuffered() == 1);

	skb->opCode = COMMIT;
	socket.PersistConnect();
	skb = pSCB->GetSendQueueHead();
	Assert::IsFalse(skb->opCode == PERSIST);
	Assert::IsTrue(pSCB->CountSendBuffered() == 1);
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

		TEST_METHOD(TestGCM_AES)
		{
			UnitTestGCM_AES();
		}

		TEST_METHOD(TestVMAC)
		{
			UnitTestVMAC();
		}


		TEST_METHOD(TestVMAC_AE)
		{
			UnitTestVMAC_AE();
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


		TEST_METHOD(TestPersistConnect)
		{
			UnitTestPersistConnect();
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
