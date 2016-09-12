// FSP_DllUnitTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

const ControlBlock::seq_t FIRST_SN = 12;

// See also CSocketItemDl::Connect2
CSocketItemDbg *GetPreparedSocket()
{
	static CommandNewSession objCommand;
	static FSP_SocketParameter parms;
	memset(& parms, sizeof(parms), 0);
	parms.onAccepting = NULL;
	parms.onAccepted = NULL;
	parms.onError = NULL;
	parms.recvSize = MAX_FSP_SHM_SIZE;	// 4MB
	parms.sendSize = 0;	// the underlying service would give the minimum, however
	parms.u.st.passive = 0;	// override what is provided by ULA
	parms.welcome = NULL;	// an active connection request shall have no welcome message
	parms.len = 0;			// or else memory access exception may occur

	IN6_ADDR addrAny = IN6ADDR_ANY_INIT;
	return (CSocketItemDbg *)CSocketItemDl::CreateControlBlock((PFSP_IN6_ADDR) & addrAny, & parms, objCommand);
}



void UnitTestCheckedRevertCommit()
{
	CSocketItemDbg *pSocketItem = GetPreparedSocket();
	ControlBlock *pSCB = pSocketItem->GetControlBlock();
	int8_t flag = 0;

	pSCB->state = NON_EXISTENT;
	int r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);

	pSCB->state = CONNECT_BOOTSTRAP;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);

	pSCB->state = PRE_CLOSED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);

	pSCB->state = CLOSED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);
	//

	pSCB->state = COMMITTING;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == -EBUSY);

	pSCB->state = COMMITTING2;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == -EBUSY);

	pSCB->state = COMMITTED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 1 && pSCB->state == ESTABLISHED);

	pSCB->state = CLOSABLE;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 1 && pSCB->state == PEER_COMMIT);

	//
	pSCB->state = CONNECT_AFFIRMING;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	pSCB->state = ESTABLISHED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	pSCB->state = PEER_COMMIT;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	pSCB->state = CLONING;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	//
	// LISTENING state is just ignored
	//
	pSCB->state = NON_EXISTENT;

	//
	//
	//
	pSCB->state = NON_EXISTENT;
	flag = EOF;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);

	pSCB->state = CONNECT_BOOTSTRAP;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);

	pSCB->state = PRE_CLOSED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);

	pSCB->state = CLOSED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);
	//

	pSCB->state = COMMITTING;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == -EBUSY);

	pSCB->state = COMMITTING2;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == -EBUSY);

	pSCB->state = COMMITTED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 1 && pSCB->state == COMMITTING);

	pSCB->state = CLOSABLE;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 1 && pSCB->state == COMMITTING2);

	//
	pSCB->state = CONNECT_AFFIRMING;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	pSCB->state = ESTABLISHED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	pSCB->state = PEER_COMMIT;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	pSCB->state = CLONING;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);
}



// Test logic of SendStream and SendInplace
void UnitTestBufferData()
{
	CSocketItemDbg *pSocketItem = GetPreparedSocket();
	ControlBlock *pSCB = pSocketItem->GetControlBlock();
	//
	static BYTE preparedTestData[MIN_RESERVED_BUF + MAX_BLOCK_SIZE]; // well, the last block is actually not used yet
	for(register int i = 0; i < sizeof(preparedTestData); i += 2)
	{
		*(short *)(preparedTestData + i) = (short)i;
	}
	//
	pSCB->state = ESTABLISHED;
	pSCB->SetRecvWindow(FIRST_SN);
	pSCB->SetSendWindow(FIRST_SN);
	printf_s("Buffer next SN = %u\n", pSCB->sendBufferNextSN);
	//
	// Emulate SendStream()
	//
	pSocketItem->SetState(ESTABLISHED);
	pSocketItem->CheckTransmitaction(0);
	pSocketItem->pendingSendBuf = preparedTestData;
	pSocketItem->BufferData(MIN_RESERVED_BUF - 2);
	printf_s("Buffer next SN = %u\n", pSCB->sendBufferNextSN);
	assert(pSCB->sendBufferNextSN == FIRST_SN + MIN_RESERVED_BUF / MAX_BLOCK_SIZE);
	//
	// As the last buffered data is imcomplete sent data is pending at the tail of the last block
	//
	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadSend();
	BYTE *buf = pSocketItem->GetSendPtr(skb);
	int r;
	for(register int i = 0; i < (MIN_RESERVED_BUF - 2) / 2; i += 2)
	{
		if(*(short *)(preparedTestData + i) != *(short *)(buf + i))
			printf_s("Short#%d differs\n", i);
	}

	// Now, reset, but this time the head packet is set
	pSCB->SetSendWindow(FIRST_SN);
	pSocketItem->SetHeadPacketIfEmpty(PERSIST);

	// now, there was no enough buffer and the data were partly buffered
	pSocketItem->pendingSendBuf = preparedTestData;
	r = pSocketItem->BufferData(MIN_RESERVED_BUF - 2);
	printf_s("%d bytes sent, %d octets remained\n", r, pSocketItem->pendingSendSize);
	printf_s("Buffer next SN = %u\n", pSCB->sendBufferNextSN);
	assert(pSCB->sendBufferNextSN == FIRST_SN + MIN_RESERVED_BUF / MAX_BLOCK_SIZE);
	//
	// Now, slide the send window, and leave one more slot for sending
	//
	pSCB->SlideSendWindowByOne();
	pSocketItem->BufferData(pSocketItem->pendingSendSize);
	printf_s("Buffer next SN = %u\n", pSCB->sendBufferNextSN);
	assert(pSCB->sendBufferNextSN == FIRST_SN + MIN_RESERVED_BUF / MAX_BLOCK_SIZE + 1);
	//
	// As there're only two block for MIN_RESERVED_BUF...Round-robin tested
	//
	skb = pSCB->HeadSend() + 1;
	buf = pSocketItem->GetSendPtr(skb);
	for(register int i = 0; i < MAX_BLOCK_SIZE; i += 2)
	{
		printf_s("%04x_%04x   ", *(short *)(preparedTestData + i), *(short *)(buf + i));
		if(i % 10 == 8)
			printf_s("\n");
		//
		assert(*(short *)(preparedTestData + i) == *(short *)(buf + i));
	}
	printf_s("\n====\n");
	//
	buf = pSocketItem->GetSendPtr(pSCB->HeadSend());
	for(register int i = 0; i < MAX_BLOCK_SIZE - 2; i += 2)
	{
		printf_s("%04x_%04x   ", *(short *)(preparedTestData + MAX_BLOCK_SIZE + i), *(short *)(buf + i));
		if(i % 10 == 8)
			printf_s("\n");
		//
		assert(*(short *)(preparedTestData + MAX_BLOCK_SIZE + i) == *(short *)(buf + i));
	}
	printf_s("\n\n");

	// TODO: test online compression
	// TODO: emulate send-receive by copying data from send buffer to receive buffer
}



//
void UnitTestPrepareToSend()
{
	CSocketItemDbg *pSocketItem = GetPreparedSocket();
	ControlBlock *pSCB = pSocketItem->GetControlBlock();
	//
	pSCB->state = ESTABLISHED;
	pSCB->SetRecvWindow(FIRST_SN);
	pSCB->SetSendWindow(FIRST_SN);
	printf_s("Buffer next SN = %u\n", pSCB->sendBufferNextSN);
	//
	// Emulate SendInplace()
	//
	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadSend();
	BYTE *buf = pSocketItem->GetSendPtr(skb);

	for(register int i = 0; i < MIN_RESERVED_BUF / 2; i += 2)
	{
		*(short *)(buf + i) = (short)i;
	}
	// One packet
	pSocketItem->SetState(ESTABLISHED);
	pSocketItem->SetNewTransaction();
	pSocketItem->PrepareToSend(buf, MAX_BLOCK_SIZE - 2, EOF);
	assert(pSCB->sendBufferNextSN == FIRST_SN + 1);
	printf_s("Buffer next SN = %u; start packet operation is %s, state is %s\n"
		, pSCB->sendBufferNextSN
		, opCodeStrings[skb->opCode]
		, stateNames[pSocketItem->GetState()]);

	// Reset, two packets
	pSocketItem->SetState(ESTABLISHED);
	pSocketItem->SetNewTransaction();
	pSCB->SetSendWindow(FIRST_SN);
	pSocketItem->PrepareToSend(buf, MIN_RESERVED_BUF - 2, EOF);
	printf_s("Buffer next SN = %u; start packet operation is %s, state is %s\n\n"
		, pSCB->sendBufferNextSN
		, opCodeStrings[skb->opCode]
		, stateNames[pSocketItem->GetState()]);
}



int _tmain(int argc, _TCHAR* argv[])
{
	UnitTestCheckedRevertCommit();

	UnitTestBufferData();

	UnitTestPrepareToSend();

	return 0;
}

