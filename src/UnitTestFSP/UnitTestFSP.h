#include "targetver.h"

#include "../FSP_SRV/fsp_srv.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <mstcpip.h>

// Headers for CppUnitTest
#define _ALLOW_KEYWORD_MACROS
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "ntdll.lib")


#ifdef MAX_CONNECTION_NUM
#undef MAX_CONNECTION_NUM
#endif
#define MAX_CONNECTION_NUM	256

#define MAX_PHY_INTERFACES	4



class ControlBlockDbg: public ControlBlock
{
	friend void UnitTestGenerateSNACK();
	friend void UnitTestAcknowledge();
	friend void UnitTestSendRecvWnd();
	friend void UnitTestResendQueue();
};


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
	//void LOCALAPI ResetVMAC()
	//{
	//	vhash_reset(& pControlBlock->mac_ctx);	// vmac_set_key
	//}

	ControlBlockDbg *GetControlBlock() const { return (ControlBlockDbg *)pControlBlock; }
	ControlBlock::PFSP_SocketBuf AllocRecvBuf(ControlBlock::seq_t seq1) { return pControlBlock->AllocRecvBuf(seq1); }
	void InstallSessionKey(BYTE key[16])
	{
		memcpy(pControlBlock->u.sessionKey, key, sizeof(key));
		CSocketItemEx::InstallSessionKey();
	}
	void SetPairOfFiberID(ALFID_T src, ALFID_T dst) { fidPair.source = src; fidPair.peer = dst; }

	friend void UnitTestSocketInState();
	friend void UnitTestReceiveQueue();
	friend void UnitTestResendQueue();
};



class CLowerInterfaceDbg: public CLowerInterface
{
public:
	PktBufferBlock *CurrentHead() { return freeBufferHead; }
	friend	void UnitTestReceiveQueue();
};



void UnitTestGenerateSNACK();
void UnitTestAcknowledge();
void UnitTestSendRecvWnd();
void UnitTestResendQueue();
