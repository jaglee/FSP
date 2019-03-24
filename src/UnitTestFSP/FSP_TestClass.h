#include "../FSP_SRV/fsp_srv.h"
#include "../Crypto/CryptoStub.h"

typedef ControlBlock * PControlBlock;

class CSocketItemExDbg: public CSocketItemEx
{
public:
	CSocketItemExDbg()
	{
		int32_t ss = MAX_BLOCK_SIZE * 2;
		int32_t sr = MAX_BLOCK_SIZE * 2;
		memset(this, 0, sizeof(CSocketItemEx));
		dwMemorySize = sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * 8;
		pControlBlock = (ControlBlock *)malloc(dwMemorySize);
		pControlBlock->Init(ss, sr);
	};

	CSocketItemExDbg(int nSend, int nRecv)
	{
		memset(this, 0, sizeof(CSocketItemEx));
		dwMemorySize = sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * (nSend + nRecv);
		pControlBlock = (ControlBlock *)malloc(dwMemorySize);
		//
		nSend *= MAX_BLOCK_SIZE;
		nRecv *= MAX_BLOCK_SIZE;
		pControlBlock->Init(nSend, nRecv);
	};

	~CSocketItemExDbg()
	{
		free(pControlBlock);
	}

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

	bool LOCALAPI AddAdhocTimer(uint32_t period, WAITORTIMERCALLBACK callback)
	{
		return (timer == NULL
			&& ::CreateTimerQueueTimer(&timer, TimerWheel::Singleton()
				, callback	// WAITORTIMERCALLBACK
				, this		// LPParameter
				, period
				, period
				, WT_EXECUTEINTIMERTHREAD));
	}

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
