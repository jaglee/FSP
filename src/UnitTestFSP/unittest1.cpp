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

// The singleton instance of the connect request queue
ConnectRequestQueue ConnectRequestQueue::requests;

// The singleton instance of the lower service interface 
CLowerInterface	CLowerInterface::Singleton;

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
	Logger::WriteMessage(noticeNames[FSP_NoticeCode::FSP_NotifyDataReady]);
	Logger::WriteMessage(noticeNames[FSP_NoticeCode::LARGEST_FSP_NOTICE]);
	Logger::WriteMessage(noticeNames[LARGEST_FSP_NOTICE + 1]);
}




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



extern "C" double CubicRoot(double);
//^defined in CubicRoot.c
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



void UnitTestSocketInState()
{
	CSocketItemExDbg socket(2, 2);
	socket.SetState(CLONING);
	bool r = socket.InStates(COMMITTING, COMMITTING2, CLONING, PRE_CLOSED, CLOSED);
	Assert::IsTrue(r);
	socket.SetState(CLOSABLE);
	r = socket.InStates(COMMITTING2, CLONING, PRE_CLOSED, CLOSED);
	Assert::IsFalse(r);
#if _MSC_VER >= 1800
	// VS2013 and above support variadic template
	r = socket.NotInStates(COMMITTING2, CLONING, PRE_CLOSED, CLOSED);
	Assert::IsTrue(r);
#endif
}



void UnitTestSocketSrvTLB()
{
	if(! CLowerInterface::Singleton.Initialize())
	{
		Logger::WriteMessage("Cannot access lower interface, aborted.\n");
		DbgRaiseAssertionFailure();
	}

	CSocketItemEx *p1 = (CSocketItemEx *)CLowerInterface::Singleton.AllocItem(2);
	Assert::IsNotNull(p1, L"There should be free item slot for listener");

	CSocketItemEx *p = (CSocketItemEx *)CLowerInterface::Singleton[2];
	Assert::IsTrue(p == p1, L"The remapped listening socket should be the same as the allocated");

	p = (CSocketItemEx *)CLowerInterface::Singleton.AllocItem();
	Assert::IsNotNull(p, L"There should be free item slot");

	IN6_ADDR addrList[MAX_PHY_INTERFACES];
	// no hint
	memset(addrList, 0, sizeof(addrList));
	ALFID_T id = CLowerInterface::Singleton.RandALFID();
	Assert::IsFalse(id == 0, L"There should be free id space");

	id = CLowerInterface::Singleton.RandALFID(addrList);
	Assert::IsFalse(id == 0, L"There should be free id space");

	sprintf_s(linebuf, "Allocated ID = %u\n", id);
	Logger::WriteMessage(linebuf);

#if 0
	for(int i = 0; i < MAX_PHY_INTERFACES; i++)
	{
		RtlIpv6AddressToString(& addrList[i], linebuf);
		Logger::WriteMessage(linebuf);
	}
#endif

	CSocketItemEx *p2 = (CSocketItemEx *)CLowerInterface::Singleton[id];
	Assert::IsFalse(p2 == p1, L"RandID shouldn't alloc the same item as AllocItem for listener");
	Assert::IsFalse(p2 == p, L"RandID shouldn't alloc the same item as AllocItem");

	CLowerInterface::Singleton.FreeItem(p1);
	CLowerInterface::Singleton.FreeItem(p);
	CLowerInterface::Singleton.FreeItem(p2);

#if 0	// should invent another test method
	CommandSyncSessionTestSub *pCmd = new CommandSyncSessionTestSub(id);
	p = (*CLowerInterface::Singleton())[*pCmd];
	Assert::IsNotNull(p, L"There should be available socket to welcome connection");
#endif
}



void UnitTestSocketRTLB()
{
	if(! CLowerInterfaceDbg::Singleton.Initialize())
	{
		Logger::WriteMessage("Cannot access lower interface, aborted.\n");
		DbgRaiseAssertionFailure();
	}
	
	CLowerInterfaceDbg *pRTLB = (CLowerInterfaceDbg *) & CLowerInterface::Singleton;

	CSocketItemExDbg *p1 = (CSocketItemExDbg *)pRTLB->AllocItem(2);
	Assert::IsNotNull(p1, L"There should be free item slot for listener");

	CSocketItemExDbg *p = (CSocketItemExDbg *)(*pRTLB)[2];
	Assert::IsTrue(p == p1, L"The remapped listening socket should be the same as the allocated");

	p = (CSocketItemExDbg *)pRTLB->AllocItem();
	Assert::IsNotNull(p, L"There should be free item slot");

	IN6_ADDR addrList[MAX_PHY_INTERFACES];
	// no hint
	memset(addrList, 0, sizeof(addrList));
	ALFID_T id = pRTLB->RandALFID();
	Assert::IsFalse(id == 0, L"There should be free id space");

	id = pRTLB->RandALFID(addrList);
	Assert::IsFalse(id == 0, L"There should be free id space");

	sprintf_s(linebuf, "Allocated ID = %u\n", id);
	Logger::WriteMessage(linebuf);

	CSocketItemExDbg *p2 = (CSocketItemExDbg *)(*pRTLB)[id];
	Assert::IsFalse(p2 == p1, L"RandID shouldn't alloc the same item as AllocItem for listener");
	Assert::IsFalse(p2 == p, L"RandID shouldn't alloc the same item as AllocItem");

	p->fidPair.peer = id;
	p->idParent = 0xABCD;
	SOCKADDR_HOSTID(p->sockAddrTo) = 0x1234;

	p2->fidPair.peer = id + 2;
	p2->idParent = 0xABCF;
	SOCKADDR_HOSTID(p2->sockAddrTo) = 0x1236;

	pRTLB->PutToRemoteTLB((CMultiplyBacklogItem *)p);
	pRTLB->PutToRemoteTLB((CMultiplyBacklogItem *)p2);

	CSocketItemExDbg *q = (CSocketItemExDbg *)pRTLB->FindByRemoteId(SOCKADDR_HOSTID(p->sockAddrTo), p->fidPair.peer, p->idParent);
	Assert::IsTrue(q == p);

	q = (CSocketItemExDbg *)pRTLB->FindByRemoteId(SOCKADDR_HOSTID(p2->sockAddrTo), p2->fidPair.peer, p2->idParent);
	Assert::IsTrue(q == p2);

	pRTLB->FreeItem(p1);
	pRTLB->FreeItem(p);
	pRTLB->FreeItem(p2);
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


void UnitTestAllocSocket()
{
	static CSocketSrvTLB & tlb = CLowerInterfaceDbg::Singleton;
	CSocketItemEx *p;
	for (register int i = 0; i < MAX_CONNECTION_NUM; i++)
	{
		p = tlb.AllocItem();
		Assert::IsNotNull(p);
		p->SetTouchTime(NowUTC());
	}
	CSocketItemExDbg *p0 = (CSocketItemExDbg *)p;

	Logger::WriteMessage("All slots allocated.");
	p = tlb.AllocItem();
	// Assert::IsNull(p);
	//^As AllocItem automatically free the slot whose ULA process is not alive, this assertion would fail

	tlb.FreeItem(p0);
	Logger::WriteMessage("One slot is free");

	p = tlb.AllocItem();
	Assert::IsNotNull(p);

	p = tlb.AllocItem();
	// Assert::IsNull(p);
	//^Again, as AllocItem automatically free the slot whose ULA process is not alive, this assertion would fail

	p0 = (CSocketItemExDbg *)tlb.AllocItem(htonl(80));
	Assert::IsNotNull(p0);
	p0->SetParentProcess();

	p = tlb.AllocItem(htonl(80));
	Assert::IsNull(p);
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
	responseZero.cookie = CalculateCookie(& cm, sizeof(cm), t1);
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


// But this is NOT a comprehensive coverage test of SelectPath
void UnitTestSelectPath()
{
	CLowerInterfaceDbg *pSrv = (CLowerInterfaceDbg *) & CLowerInterfaceDbg::Singleton;
	if(! pSrv->Initialize())
	{
		Logger::WriteMessage("Cannot access lower interface, aborted.\n");
		DbgRaiseAssertionFailure();
	}

	FSP_SINKINF nearInfo;
	SOCKADDR_INET addr;

	pSrv->sdSet.fd_count = 5;
	pSrv->addresses[0].sin6_addr = in6addr_linklocalprefix;
	pSrv->addresses[1].sin6_addr = in6addr_6to4prefix;
	pSrv->addresses[2].sin6_addr = in6addr_teredoprefix;
	// ULA
	pSrv->addresses[3].sin6_addr.u.Word[0] = 0x00FC;
	pSrv->addresses[3].sin6_addr.u.Word[1] = 0x0000;
	pSrv->addresses[3].sin6_addr.u.Word[2] = 0x0000;
	pSrv->addresses[3].sin6_addr.u.Word[3] = 0x0000;
	pSrv->addresses[3].sin6_addr.u.Word[4] = 0x0000;
	pSrv->addresses[3].sin6_addr.u.Word[5] = 0x0000;
	pSrv->addresses[3].sin6_addr.u.Word[6] = 0x0000;
	pSrv->addresses[3].sin6_addr.u.Word[7] = 0x0100;

	pSrv->addresses[4].sin6_addr = pSrv->addresses[3].sin6_addr;
	pSrv->addresses[4].sin6_addr.u.Word[0] = 0x00E0;

	pSrv->interfaces[0] = 1;
	pSrv->interfaces[1] = 2;
	pSrv->interfaces[2] = 3;
	pSrv->interfaces[3] = 4;
	pSrv->interfaces[4] = 5;

	addr.Ipv6.sin6_addr = in6addr_linklocalprefix;
	pSrv->SelectPath(& nearInfo, 2, 1, & addr);
	Assert::IsTrue(nearInfo.idALF == 2
		//&& nearInfo.ipi6_ifindex == 1
		&& nearInfo.ipi_addr == *(uint32_t *) & in6addr_linklocalprefix.u);

	// then in6addr_6to4prefix
	addr.Ipv6.sin6_addr = in6addr_6to4prefix;
	pSrv->SelectPath(& nearInfo, 2, 2, & addr);
	Assert::IsTrue(nearInfo.idALF == 2
		//&& nearInfo.ipi6_ifindex == 2
		&& nearInfo.ipi_addr == *(uint32_t *) & in6addr_6to4prefix.u);

	// then match terodo tunnelling
	addr.Ipv6.sin6_addr = in6addr_teredoprefix;
	pSrv->SelectPath(& nearInfo, 2, 3, & addr);
	Assert::IsTrue(nearInfo.idALF == 2
		//&& nearInfo.ipi6_ifindex == 3
		&& nearInfo.ipi_addr == *(uint32_t *) & in6addr_teredoprefix.u);

	// then a Unique Local Address (but site-local is obsolete)
	addr.Ipv6.sin6_addr.u.Word[0] = 0x00FC;
	addr.Ipv6.sin6_addr.u.Word[1] = 0x0000;
	addr.Ipv6.sin6_addr.u.Word[2] = 0x0000;
	addr.Ipv6.sin6_addr.u.Word[3] = 0x0000;
	pSrv->SelectPath(& nearInfo, 2, 4, & addr);
	Assert::IsTrue(nearInfo.idALF == 2
		//&& nearInfo.ipi6_ifindex == 4
		&& nearInfo.ipi_addr == 0xFC);

	// lastly the global unique address
	addr.Ipv6.sin6_addr.u.Word[0] = 0x00E0;
	addr.Ipv6.sin6_addr.u.Word[1] = 0x0000;
	addr.Ipv6.sin6_addr.u.Word[2] = 0x0000;
	addr.Ipv6.sin6_addr.u.Word[3] = 0x0000;
	pSrv->SelectPath(& nearInfo, 2, 5, & addr);
	Assert::IsTrue(nearInfo.idALF == 2
		//&& nearInfo.ipi6_ifindex == 5
		&& nearInfo.ipi_addr == 0xE0);
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

		TEST_METHOD(TestCubicRoot)
		{
			UnitTestCubicRoot();
		}

		TEST_METHOD(TestGCM_AES)
		{
			UnitTestGCM_AES();
		}

		TEST_METHOD(TestOCB_MAC)
		{
			UnitTestOCB_MAC();
		}


		TEST_METHOD(TestSocketSrvTLB)
		{
			UnitTestSocketSrvTLB();
		}


		TEST_METHOD(TestSocketRTLB)
		{
			UnitTestSocketRTLB();
		}


		TEST_METHOD(TestConnectQueue)
		{
			UnitTestConnectQueue();
		}


		TEST_METHOD(TestAllocSocket)
		{
			UnitTestAllocSocket();
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

		TEST_METHOD(TestSelectPath)
		{
			UnitTestSelectPath();
		}

	};
}
