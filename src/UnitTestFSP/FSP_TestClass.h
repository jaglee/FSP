#include "../FSP_SRV/fsp_srv.h"
#include "../Crypto/CryptoStub.h"

#ifdef MAX_CONNECTION_NUM
#undef MAX_CONNECTION_NUM
#endif
#define MAX_CONNECTION_NUM	256

#define MAX_PHY_INTERFACES	4

typedef ControlBlock * PControlBlock;

class CSocketItemExDbg: public CSocketItemEx
{
public:
	CSocketItemExDbg()
	{
		int32_t ss = MAX_BLOCK_SIZE * 2;
		int32_t sr = MAX_BLOCK_SIZE * 2;
		memset(this, 0, sizeof(CSocketItemEx));
		pControlBlock = (ControlBlock *)malloc
			(sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * 8);
		pControlBlock->Init(ss, sr);
	};
	CSocketItemExDbg(int nSend, int nRecv)
	{
		// isMilky = 0;	// RespondToSNACK cares it
		hMemoryMap = NULL;
		hEvent = NULL;
		pControlBlock = (ControlBlock *)malloc
			(sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * (nSend + nRecv));
		//
		nSend *= MAX_BLOCK_SIZE;
		nRecv *= MAX_BLOCK_SIZE;
		pControlBlock->Init(nSend, nRecv);
	};
	~CSocketItemExDbg()
	{
		free(pControlBlock);
	}
	//void LOCALAPI ResetVMAC()
	//{
	//	vhash_reset(& pControlBlock->mac_ctx);	// vmac_set_key
	//}
	void SetState(FSP_Session_State s) { CSocketItemEx::SetState(s); }

	bool NotInStates(FSP_Session_State first, FSP_Session_State second)
	{
		return lowState != first && lowState != second;
	}

#if _MSC_VER >= 1800
	// VS2013 and above support variadic template
	template<typename... States>
	bool NotInStates(FSP_Session_State first, States ... rest)
	{
		return lowState != first && NotInStates(rest...);
	}
#endif

	PControlBlock GetControlBlock() const { return PControlBlock(pControlBlock); }
	ControlBlock::PFSP_SocketBuf AllocRecvBuf(ControlBlock::seq_t seq1) { return pControlBlock->AllocRecvBuf(seq1); }
	void InstallSessionKey(BYTE key[FSP_MIN_KEY_SIZE])
	{
		CommandInstallKey cmd(pControlBlock->sendBufferNextSN, INT32_MAX);
		memcpy(cmd.ikm, key, FSP_MIN_KEY_SIZE);
		pControlBlock->connectParams.keyBits = FSP_MIN_KEY_SIZE * 8;
		pControlBlock->SnapshotReceiveWindowRightEdge();
		CSocketItemEx::InstallSessionKey(cmd);
	}
	void SetPairOfFiberID(ALFID_T src, ALFID_T dst) { fidPair.source = src; fidPair.peer = dst; }

	friend void UnitTestSocketRTLB();
	friend void UnitTestICC();
	friend void UnitTestHMAC();
	friend void UnitTestSocketInState();
	friend void FlowTestRetransmission();
	friend void PrepareFlowTestResend(CSocketItemExDbg &, PControlBlock &);
};



class CLowerInterfaceDbg: public CLowerInterface
{
public:
	friend void UnitTestSelectPath();
};
