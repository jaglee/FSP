#include "../FSP_SRV/fsp_srv.h"

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
		// isMilky = 0;	// RespondToSNACK cares it
		hMemoryMap = NULL;
		hEvent = NULL;
		pControlBlock = (ControlBlock *)malloc
			(sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * 8);
		pControlBlock->Init(MAX_BLOCK_SIZE * 2, MAX_BLOCK_SIZE * 2);
	};
	CSocketItemExDbg(int nSend, int nRecv)
	{
		// isMilky = 0;	// RespondToSNACK cares it
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
	void SetState(FSP_Session_State s) { CSocketItemEx::SetState(s); }

	PControlBlock GetControlBlock() const { return PControlBlock(pControlBlock); }
	ControlBlock::PFSP_SocketBuf AllocRecvBuf(ControlBlock::seq_t seq1) { return pControlBlock->AllocRecvBuf(seq1); }
	void InstallSessionKey(BYTE key[FSP_MIN_KEY_SIZE])
	{
		memcpy(& pControlBlock->connectParams, key, FSP_MIN_KEY_SIZE);
		pControlBlock->connectParams.keyLength = FSP_MIN_KEY_SIZE;
		pControlBlock->connectParams.initialSN = UINT16_MAX;
		CSocketItemEx::InstallSessionKey();	// with a quite short life
	}
	void SetPairOfFiberID(ALFID_T src, ALFID_T dst) { fidPair.source = src; fidPair.peer = dst; }

	friend void UnitTestSocketInState();
	friend void UnitTestReceiveQueue();
	friend void FlowTestRetransmission();
	friend void PrepareFlowTestResend(CSocketItemExDbg &, PControlBlock &);
};



class CLowerInterfaceDbg: public CLowerInterface
{
public:
	PktBufferBlock *CurrentHead() { return freeBufferHead; }
	friend	void UnitTestReceiveQueue();
};
