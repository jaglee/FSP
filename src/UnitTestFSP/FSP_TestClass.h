#include "../FSP_SRV/fsp_srv.h"
#include "../Crypto/CryptoStub.h"

typedef ControlBlock * PControlBlock;

class CSocketItemExDbg: public CSocketItemEx
{
public:
	int Init(int nSend, int nRecv)
	{
		int m = offsetof(SocketItemEx, timer);
		bzero((octet *)this + m, m);
		//
		dwMemorySize = (int32_t)sizeof(ControlBlock)
			+ int32_t(sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * (nSend + nRecv);
		pControlBlock = (ControlBlock*)malloc(dwMemorySize);
		if (pControlBlock == NULL)
			return -ENOMEM;
		//
		nSend *= MAX_BLOCK_SIZE;
		nRecv *= MAX_BLOCK_SIZE;
		return pControlBlock->Init(nSend, nRecv);
	}
	CSocketItemExDbg(int nSend = 2, int nRecv = 2) { Init(nSend, nRecv); };

	~CSocketItemExDbg()
	{
		free(pControlBlock);
	}

	void SetState(FSP_Session_State s) { CSocketItemEx::SetState(s); }
	void SetLowState(FSP_Session_State s) { lowState = s; }
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

	SProcessRoot* GetProcessRoot() { return rootULA; }
	PControlBlock GetControlBlock() const { return PControlBlock(pControlBlock); }
	ControlBlock::PFSP_SocketBuf AllocRecvBuf(ControlBlock::seq_t seq1) { return pControlBlock->AllocRecvBuf(seq1); }

	// Note that the first packet to apply the new session key is always the one buffered next
	void InstallSessionKey(BYTE ikm[FSP_MIN_KEY_SIZE])
	{
		CommandInstallKey cmd(0, INT32_MAX);	// Application Layer Fiber ID is not exploited here, however.
		pControlBlock->connectParams.keyBits = FSP_MIN_KEY_SIZE * 8;
		pControlBlock->SnapshotReceiveWindowRightEdge();

		// CSocketItemEx::InstallSessionKey(cmd); ::
		contextOfICC.isPrevSendCRC = contextOfICC.isPrevRecvCRC
			= (InterlockedExchange64((int64_t*)&contextOfICC.keyLifeRemain, cmd.keyLife) == 0);
		contextOfICC.noEncrypt = (pControlBlock->noEncrypt != 0);
		contextOfICC.snFirstSendWithCurrKey = pControlBlock->sendBufferNextSN;
		contextOfICC.snFirstRecvWithCurrKey = pControlBlock->connectParams.expectedSN;
		contextOfICC.InitiateExternalKey(ikm, FSP_MIN_KEY_SIZE);
	}

	void SetPairOfFiberID(ALFID_T src, ALFID_T dst) { fidPair.source = src; fidPair.peer = dst; }

	// For test algorithm for generating KEEP_ALIVE packet in timer.cpp
	int32_t LOCALAPI GenerateSNACK(FSP_KeepAlivePacket&);

	friend void UnitTestAllocSocket();
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
