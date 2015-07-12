/*
 * Shared implementation of quasi-queue for commands and their returned values between DLL and LLS
 *
    Copyright (c) 2012, Jason Gao
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    - Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT,INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
 */
#define WIN32_LEAN_AND_MEAN
#define STRICT
#include <Windows.h>
#include <time.h>
#include <stdio.h>
#include <assert.h>

#include <stdlib.h>

#include "FSP.h"
#include "FSP_Impl.h"


// Reflexing string representation of operation code, for debug purpose
const char * CStringizeOpCode::names[LARGEST_OP_CODE + 1] =
{
	"UNDEFINED/Shall not appear!",
	"INIT_CONNECT",
	"ACK_INIT_CONNECT",
	"CONNECT_REQUEST",
	"ACK_CONNECT_REQ",
	"RESET",
	"PERSIST",		// Alias: KEEP_ALIVE, DATA_WITH_ACK,
	"PURE_DATA",	// Without any optional header
	"COMMIT",
	"ACK_FLUSH",
	"RESUME",		// RESUME or RESURRECT connection, may piggyback payload
	"RELEASE",
	"MULTIPLY",		// To clone connection, may piggyback payload
	"KEEP_ALIVE",
	"RESERVED_CODE14",
	"RESERVED_CODE15",
	"RESERVED_CODE16",
	//
	"MOBILE_PARAM",
	"SELECTIVE_NACK"
} ;


// Reflexing string representation of FSP_Session_State and FSP_ServiceCode, for debug purpose
// Place here because value of the state or notice/servic code is stored in the control block
const char * CStringizeState::names[LARGEST_FSP_STATE + 1] =
{
	"NON_EXISTENT",
	// the passiver listener to folk new connection handle:
	"LISTENING",
	// initiative, after sending initiator's check code, before getting responder's cookie
	// timeout to retry or NON_EXISTENT:
	"CONNECT_BOOTSTRAP",
	// after getting legal CONNECT_REQUEST and sending back ACK_CONNECT_REQ
	// before getting first PERSIST. timeout to NON_EXISTENT:
	"CHALLENGING",
	// after getting responder's cookie and sending formal CONNECT_REQUEST
	// before getting ACK_CONNECT_REQ, timeout to retry or NON_EXISTENT
	"CONNECT_AFFIRMING",
	// initiator: after getting the ACK_CONNECT_REQ 
	// responder: after getting the first PERSIST
	// no default timeout. however, implementation could arbitrarily limit a session life
	"ESTABLISHED",
	// after sending FLUSH, before getting all packet-in-flight acknowledged
	"COMMITTING",
	// after receiving FLUSH
	"PEER_COMMIT",
	// after both receiving and sending FLUSH, before getting all packet-in-flight acknowledged
	"COMMITTING2",
	// after getting all packet-in-flight acknowledged, including the FLUSH packet, without receiving peer's FLUSH
	"COMMITTED",
	// after getting all packet-in-flight acknowledged and having received peer's FLUSH and the FLUSH is acknowledgable
	"CLOSABLE",
	// after ULA shutdown the connection in CLOSABLE state gracefully
	// it isn't a pseudo-state alike TCP, but a physical, resumable/reusable state
	"PRE_CLOSED",
	// after ULA shutdown the connection in CLOSABLE state gracefully
	// it isn't a pseudo-state alike TCP, but a physical, resumable/reusable state
	"CLOSED",
	// context cloned by ConnectMU:
	"CLONING",
	// after sending RESUME, before RESUME acknowledged
	"RESUMING",
	// resurrect from CLOSED:
	"QUASI_ACTIVE",
};

const char * CStringizeNotice::names[LARGEST_FSP_NOTICE + 1] =
{
	"NullCommand",
	// 1~15: DLL to LLS
	"FSP_Listen",		// register a passive socket
	"InitConnection",	// register an initiative socket
	"FSP_NotifyAccepting",	//  = SynConnection,	// a reverse command to make context ready
	"FSP_Reject",		// a reverse command. used to be FSP_Preclose/FSP_Timeout, forward command is FSP_Reject
	"FSP_Dispose",		// AKA Reset. dispose the socket. connection might be aborted
	"FSP_Start",		// send a start packet such as MULTIPLY, PERSIST and transactional COMMIT
	"FSP_Send",			// send a packet/a group of packets
	"FSP_Urge",			// send a packet urgently, mean to urge COMMIT
	"FSP_Resume",		// cancel COMMIT(unilateral adjourn) or send RESUME
	"FSP_Shutdown",		// close the connection
	// 11-15, 5 reserved
	"Reserved11",
	"Reserved12",
	"Reserved13",
	"Reserved14",
	"Reserved15",
	// 16~23: LLS to DLL in the backlog
	"FSP_NotifyAccepted",
	"FSP_NotifyDataReady",
	"FSP_NotifyBufferReady",
	"FSP_NotifyReset",
	"FSP_NotifyToCommit",
	"FSP_NotifyFlushed",
	"FSP_NotifyFinish",
	"FSP_NotifyRecycled",
	// 24~31: near end error status
	"FSP_IPC_CannotReturn",	// LLS cannot return to DLL for some reason
	"FSP_MemoryCorruption",
	"FSP_NotifyOverflow",
	"FSP_NotifyTimeout",
	"FSP_NotifyNameResolutionFailed"
};


// assume it is atomic (the assumption might be broken!)
const char * CStringizeOpCode::operator[](int i)
{
	static char errmsg[] = "Unknown opCode: 0123467890123";
	if (i < 0 || i > LARGEST_OP_CODE)
	{
		_itoa_s(i, &errmsg[16], 14, 10);
		return &errmsg[0];
	}
	return CStringizeOpCode::names[i];
}

// assume it is atomic (the assumption might be broken!)
const char * CStringizeState::operator[](int i)
{
	static char errmsg[] = "Unknown state: 0123467890123";
	if (i < 0 || i > CLOSED)
	{
		_itoa_s(i, &errmsg[15], 14, 10);
		return &errmsg[0];
	}
	return CStringizeState::names[i];
}

// assume it is atomic (the assumption might be broken!)
const char * CStringizeNotice::operator[](int i)
{
	static char errmsg[] = "Unknown notice: 0123467890123";
	if (i < 0 || i > LARGEST_FSP_NOTICE)
	{
		_itoa_s(i, &errmsg[16], 14, 10);
		return &errmsg[0];
	}
	return CStringizeNotice::names[i];
}

CStringizeOpCode opCodeStrings;
CStringizeState stateNames;
CStringizeNotice noticeNames;



// Remark
//	There would be at least two item in the queue
template<typename TLogItem>
int TSingleProviderMultipleConsumerQ<TLogItem>::InitSize(int n)
{
	if(n <= 1)
		return 0;
	int m = 0;
	while((n >>= 1) > 0)
		m++;
	// assume memory has been zeroed
	capacity = 1 << m;
	return capacity;
}


// Given
//	TLogItem	the item to be pushed
// Return
//	non-negative on success, or negative on failure
// Remark
//	capacity must be some power of 2
template<typename TLogItem>
int LOCALAPI TSingleProviderMultipleConsumerQ<TLogItem>::Push(const TLogItem *p)
{
	if(InterlockedIncrementAcquire(& nProvider) > 1)
	{
		InterlockedDecrementRelease(& nProvider);
		return -EBUSY;
	}
	if(count >= capacity || nProvider > 1)
	{
		InterlockedDecrementRelease(& nProvider);
		return -ENOMEM;
	}

	register int i = tailQ;
	q[i] = *p;
	tailQ = (i + 1) & (capacity - 1);

	count++;
	InterlockedDecrementRelease(& nProvider);
	return i;
}


// Given
//	TLogItem *		the place holder of store the value of the first item in the queue
// Return
//	non-negative on success, or negative on failure
// Remark
//	capacity must be some power of 2
//	It is assumed that there is only one producer(optimistic push) but may be multiple consumer(conservative pop)
template<typename TLogItem>
int LOCALAPI TSingleProviderMultipleConsumerQ<TLogItem>::Pop(TLogItem *p)
{
	while(_InterlockedCompareExchange8(& mutex, 1, 0))
	{
		Sleep(0);	// just yield out the CPU time slice
	}

	register int i = headQ;
	if(count == 0)
	{
		i = -ENOENT;
		goto l_bailout;
	}

	while(count - 1 == 0 && nProvider)
	{
		Sleep(0);
		// See also TSingleProviderMultipleConsumerQ::Push, should be very rare
	}

	*p = q[i];
	headQ = (i + 1) & (capacity - 1);
	count--;

l_bailout:
	_InterlockedExchange8(& mutex, 0);	// with memory barrier release semantics assumed
	return i;
}



// Remark
//	It is assumed that there is only one producer(optimistic push) but may be multiple consumer(conservative pop)
//	here we rely on a conservative memory model to make sure q[i] is written before tailQ is set
//	UNRESOLVED!? disable certain compiler optimization, out-of-order execution may break the assumption
//	If provider lock could not be obtained it will return true ('collision found') instead of raising an 'EBUSY' exception
bool LOCALAPI ControlBlock::HasBacklog(const BackLogItem *p)
{
	if(InterlockedIncrementAcquire(& backLog.nProvider) > 1)
	{
		InterlockedDecrementRelease(& backLog.nProvider);
		return true;
	}

	if(backLog.count <= 0)
	{
		InterlockedDecrementRelease(& backLog.nProvider);
		return false;	// empty queue
	}

	// it is possible that phantom read occurred
	register int i = backLog.headQ;
	register int k = backLog.tailQ;
	BackLogItem *pQ = backLog.q;
	do
	{
		if(pQ[i].idRemote == p->idRemote && pQ[i].salt == p->salt)
		{
			InterlockedDecrementRelease(& backLog.nProvider);
			return true;
		}
		i = (i + 1) & (backLog.capacity - 1);
	} while(i != k);
	//
	InterlockedDecrementRelease(& backLog.nProvider);
	return false;
}



// these functions may not implemented nor declared inline, or else linkage error might occur
int LOCALAPI ControlBlock::PushBacklog(const BackLogItem *p)
{
	return backLog.Push(p); 
}



int LOCALAPI ControlBlock::PopBacklog(BackLogItem *p) 
{
	return backLog.Pop(p);
}


// Given
//	FSP_ServiceCode	the notice code, shall not be NullCommand(0)
// Return
//	0 if no error
//	1 if success with warning 'duplicated'
//	-ENOMEM if no space on the queue (should never happen!)
// Remark
//	ULA should know that duplicate notices are merged
int LOCALAPI ControlBlock::PushNotice(FSP_ServiceCode c)
{
	register char r;
	for(register int i = 0; i < FSP_MAX_NUM_NOTICE; i++)
	{
		r = _InterlockedCompareExchange8((char *)(notices + i), c, NullCommand);
		if(r == NullCommand)
			return 0;
		if(r == c)
			return 1;
	}
	return -ENOMEM;
}


// Return the notice code on success, or NullCommand(0) on empty
// Remark
//	ULA should know that notices are out-of-band, emergent messages which might be processed out-of-order
FSP_ServiceCode ControlBlock::PopNotice()
{
	register char r;
	for(register int i = 0; i < FSP_MAX_NUM_NOTICE; i++)
	{
		r = _InterlockedExchange8((char *)(notices + i), NullCommand);
		if(r != 0)
			return FSP_ServiceCode(r);
	}
	return NullCommand;
}



// Given
//	int32_t		the upper limit size in bytes of the send buffer
//	int32_t 	the upper limit size in bytes of the receive buffer
// Do
//	initialize the session control block, primarily the send and receive windows descriptors
// Return
//	0 if no error, negative is the error number
// Remark
//	the caller should make sure enough memory has been allocated and zeroed
int LOCALAPI ControlBlock::Init(int32_t sendSize, int32_t recvSize) 
{
	memset(this, 0, sizeof(ControlBlock));
	// notice01 = notice10 = NullCommand;
	backLog.InitSize();

	recvBufferBlockN = recvSize / MAX_BLOCK_SIZE;
	sendBufferBlockN = sendSize / MAX_BLOCK_SIZE;
	if(recvBufferBlockN <= 0 || sendBufferBlockN <= 0)
		return -EDOM;

	// safely assume the buffer blocks and the descriptor blocks of the send and receive queue are continuous
	int sizeDescriptors = sizeof(FSP_SocketBuf) * (recvBufferBlockN + sendBufferBlockN);

	// here we let it interleaved:
	// send buffer descriptors, receive buffer descriptors, receive buffer blocks and send buffer blocks
	// we're sure that FSP_SocketBuf itself is 64-bit aligned. to make buffer block 64-bit aligned
	_InterlockedExchange(& sendBufDescriptors, (sizeof(ControlBlock) + 7) & 0xFFFFFFF8);
	_InterlockedExchange(& recvBufDescriptors, sendBufDescriptors + sizeof(FSP_SocketBuf) * sendBufferBlockN);
	_InterlockedExchange(& recvBuffer, (sendBufDescriptors + sizeDescriptors + 7) & 0xFFFFFFF8);
	_InterlockedExchange(& sendBuffer, recvBuffer + recvBufferBlockN * MAX_BLOCK_SIZE);

	memset((BYTE *)this + sendBufDescriptors, 0, sizeDescriptors);

	return 0;
}


// Given
//	uint16_t	the upper limit of the capacity of the backlog, should be no greater than USHRT_MAX
// Do
//	initialize the backlog queue
// Return
//	0 if no error, negative is the error number
// Remark
//	The caller should make sure enough memory has been allocated and zeroed
int LOCALAPI ControlBlock::Init(uint16_t nLog) 
{
	memset(this, 0, sizeof(ControlBlock));
	// notice01 = notice10 = NullCommand;
	int n = backLog.InitSize(nLog);
	return (n <= 0 ? -ENOMEM : 0);
}


// Return
//	The block descriptor of the first available send buffer
// Remark
//	It is assumed that the caller have gain exclusive access on the control block among providers
//	However, LLS may change (sendWindowHeadPos, sendWindowFirstSN) simultaneously, non-atomically
//	LLS should check the validity of each descriptor to prevent memory access violation
ControlBlock::PFSP_SocketBuf ControlBlock::GetSendBuf()
{
	int i = CountSendBuffered();
	if(i < 0 || i >= sendBufferBlockN)
		return NULL;

	register PFSP_SocketBuf p = HeadSend() + sendBufferNextPos++;
	p->InitFlags();	// and locked
	sendBufferNextSN++;
	RoundSendBufferNextPos();

	return p;
}


// Given
//	int &
//		[_In_]  the minimum buffer size requested
//		[_Out_] the size of the next free send buffer block, no less than what is requested
// Return
//	The start address of the next free send buffer block whose size might be less than requested
// Remark
//	It is assumed that the caller have gain exclusive access on the control block among providers
//	However, LLS may change (sendWindowHeadPos, sendWindowFirstSN) simultaneously, non-atomically
void * LOCALAPI ControlBlock::InquireSendBuf(int & m)
{
	if (m <= 0)
	{
		m = -EDOM;
		return NULL;
	}
	if(m > MAX_BLOCK_SIZE * (sendBufferBlockN - CountSendBuffered()))
	{
		m = -ENOMEM;
		return NULL;
	}
	// and no memory overwritten even it happens that sendBufferNextPos == sendWindowHeadPos
	register int i = sendBufferNextPos;
	if(i == sendWindowHeadPos)
	{
		m = MAX_BLOCK_SIZE * ClearSendWindow();
		return (BYTE *)this + sendBuffer;
	}

	m = (i > sendWindowHeadPos)
		? MAX_BLOCK_SIZE * (sendBufferBlockN - i) 
		: MAX_BLOCK_SIZE * (sendWindowHeadPos - i);
	return (BYTE *)this + sendBuffer + i * MAX_BLOCK_SIZE;
}


// Given
//	buf: the buffer pointer, which should be returned by InquireSendBuf
//	n: the size of the buffer, which should be no greater than that returned by InquireSendBuf
// Do
//	put the inplace send buffer(get by InquireSendBuf) into the send queue
//	update 'len', flags, timeOut and sequence number
// Return
//	number of block split
//	-EFAULT if the first parameter is illegal (buf is not that returned by InquireSendBuf)
//	-ENOMEM if too larger size requested
//	-EDOM if the second or third parameter is illegal
// Remark
//	would check parameters. the caller should check the returned value
//	toBeContinued would be ignored (set to false) if len is not a multiple of MAX_BLOCK_SIZE
int ControlBlock::MarkSendQueue(void * buf, int n, bool toBeContinued)
{
	if(n <= 0 || n % MAX_BLOCK_SIZE != 0 && toBeContinued)
		return -EDOM;

	register int m = n;
	if(InquireSendBuf(m) != buf)
		return -EFAULT;
	if(m < n)
		return -ENOMEM;

	register PFSP_SocketBuf p = HeadSend() + ((BYTE *)buf - (BYTE *)this - sendBuffer) / MAX_BLOCK_SIZE;
	// p now is the descriptor of the first available buffer block
	m = (n - 1) / MAX_BLOCK_SIZE;
	for(int j = 0; j < m; j++)
	{
		p->InitFlags();	// and locked
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		p->len = MAX_BLOCK_SIZE;
		p->SetFlag<TO_BE_CONTINUED>();
		p->SetFlag<IS_COMPLETED>();
		p->Unlock();	// so it could be send
		p++;
	}
	//
	p->InitFlags();	// and locked
	p->version = THIS_FSP_VERSION;
	p->opCode = PURE_DATA;
	p->len = n - MAX_BLOCK_SIZE * m;
	p->SetFlag<TO_BE_CONTINUED>(toBeContinued && p->len == MAX_BLOCK_SIZE);
	p->SetFlag<IS_COMPLETED>();
	p->Unlock();
	//
	sendBufferNextPos += m + 1;
	sendBufferNextSN += m + 1;
	RoundSendBufferNextPos();
	// assert(sendBufferNextPos <= sendBufferBlockN);	// See also InquireSendBuf
	return (m + 1);
}



// Given
//	FSP_NormalPacketHeader	the place-holder of sequence number and flags
//	PFSP_SocketBuf			the pointer to the send buffer block descriptor
//	seq_t					the sequence number of the packet meant to be set
// Do
//	Set the sequence number, expected acknowledgment sequencenumber,
//	flags and the advertised receive window size field of the FSP header 
void LOCALAPI ControlBlock::SetSequenceFlags(FSP_NormalPacketHeader *pHdr, PFSP_SocketBuf skb, seq_t seq)
{
	pHdr->expectedSN = htobe32(recvWindowNextSN);
	pHdr->sequenceNo = htobe32(seq);
	pHdr->ClearFlags();	// pHdr->u.flags = 0;
	if (skb->GetFlag<TO_BE_CONTINUED>())
		pHdr->SetFlag<ToBeContinued>();
	else
		pHdr->ClearFlag<ToBeContinued>();
	// UNRESOLVED! compressed? ECN?
	// here we needn't check memory corruption as mishavior only harms himself
	pHdr->SetRecvWS(RecvWindowSize());
}



// Given
//	FSP_NormalPacketHeader	the place-holder of sequence number and flags
//	seq_t					the sequence number to be accumulatively acknowledged 
// Do
//	Set the sequence number, expected acknowledgment sequencenumber,
//	flags and the advertised receive window size field of the FSP header 
void LOCALAPI ControlBlock::SetSequenceFlags(FSP_NormalPacketHeader *pHdr, seq_t seqExpected)
{
	pHdr->sequenceNo = htobe32(sendWindowNextSN);
	pHdr->expectedSN = htobe32(seqExpected);
	pHdr->ClearFlags();
	pHdr->SetRecvWS(RecvWindowSize());
}



// Given
//	FSP_NormalPacketHeader	the place-holder of sequence number and flags
// Do
//	Set the default sequence number, expected acknowledgment sequencenumber,
//	flags and the advertised receive window size field of the FSP header 
void LOCALAPI ControlBlock::SetSequenceFlags(FSP_NormalPacketHeader *pHdr)
{
	pHdr->expectedSN = htobe32(recvWindowNextSN);
	pHdr->sequenceNo = htobe32(sendWindowNextSN);
	pHdr->ClearFlags();
	pHdr->SetRecvWS(RecvWindowSize());
}



// Given
//	seq_t		the sequence number that is to be assigned to the new allocated packet buffer
// Do
//	Get a receive buffer block from the receive window and set the sequence number
// Return
//	The locked descriptor of the receive buffer block
// Remark
//	It is assumed that it is unnecessary to worry about atomicity of (recvWindowNextSN, recvWindowNextPos)
//  the caller should check and handle duplication of the received data packet
ControlBlock::PFSP_SocketBuf LOCALAPI ControlBlock::AllocRecvBuf(seq_t seq1)
{
	if(int(seq1 - recvWindowFirstSN) < 0)
		return NULL;	// an outdated packet received
	//
	int d = int(seq1 - recvWindowNextSN);
	if(d >= RecvWindowSize())
		return NULL;

	PFSP_SocketBuf p;
	if(d == 0)
	{
		p = HeadRecv() + recvWindowNextPos++;
		recvWindowNextSN++;
		if(recvWindowNextPos - recvBufferBlockN >= 0)
			recvWindowNextPos -= recvBufferBlockN;
	}
	else
	{
		bool notOutOfOrder = (d > 0);
		d += recvWindowNextPos;
		if(d - recvBufferBlockN >= 0)
			d -= recvBufferBlockN;
		else if(d < 0)
			d += recvBufferBlockN;
		p = HeadRecv() + d;
		//
		if(notOutOfOrder)
		{
			recvWindowNextSN = seq1 + 1;
			recvWindowNextPos = d + 1 >= recvBufferBlockN ? 0 : d + 1;
		}
		else if(p->GetFlag<IS_FULFILLED>())
		{
			return p;	// this is an out-of-order packet and the payload buffer has been filled already
		}
	}
	//
	p->InitFlags();	// and locked
	return p;
}


// Given
//	int & : [_Out_] place holder of the number of bytes [to be] peeked.
//	bool &: [_Out_] place holder of the flag telling whether there are further data to receive
// Return
//	Start address of the received message
// Remark
//	If the returned value is NULL, stored in int & [_Out_] is the error number
//	-EPERM		the parameter value is not permited
//	-EACCES		the buffer block is corrupted and not accessible
//	-EFAULT		the descriptor is corrupted (illegal payload length:
//				payload length of an intermediate packet of a message should be MAX_BLOCK_SIZE,
//				payload length of any packet should be no less than 0 and no greater than MAX_BLOCK_SIZE)
//	It is assumed that the timeIn field of the descriptor of a free receive buffer block is 0
void * LOCALAPI ControlBlock::InquireRecvBuf(int & nIO, bool & toBeContinued)
{
	PFSP_SocketBuf p = GetFirstReceived();
	void * const pr = GetRecvPtr(p);	// the pointer value returned
	//
	const int tail = recvWindowNextPos;
	int i, m;
	// assert(tail < recvBufferBlockN);	// it may happen to be false because of parallism
	if(tail < recvWindowHeadPos || tail > recvBufferBlockN)
		m = recvBufferBlockN - recvWindowHeadPos;
	else
		m = tail - recvWindowHeadPos;
	nIO = 0;
	toBeContinued = true;
	for(i = 0; i < m && p->GetFlag<IS_FULFILLED>(); i++)
	{
		if(p->len > MAX_BLOCK_SIZE || p->len < 0)
		{
			nIO = -EFAULT;
			return NULL;
		}
		//
		if (p->GetFlag<IS_DELIVERED>())
		{
			TRACE_HERE("To double deliver a packet?");
			return NULL;
		}
		p->SetFlag<IS_DELIVERED>();
		//
		recvWindowFirstSN++;
		nIO += p->len;
		//
		if(! p->GetFlag<TO_BE_CONTINUED>())
		{
			toBeContinued = false;
			i++;
			break;
		}
		if(p->len != MAX_BLOCK_SIZE)
		{
			nIO = -EFAULT;
			return NULL;
		}
		//
		p++;
	}
	//
	recvWindowHeadPos += i;
	if(recvWindowHeadPos - recvBufferBlockN >= 0)
		recvWindowHeadPos -= recvBufferBlockN;
	//
	return pr;	// while nIO == 0 is legal
}



// Given
//	seq_t &			[_Out_]	the accumulatively acknowledged sequence number
//	GapDescriptor *	output buffer of gap descriptors
//	int				capacity of the buffer, in number of GapDescriptors
// Return
//	positive integer: number of gaps found
//	-EDOM		input parameter error
//	-EFAULT		session control block is corrupted (e.g.illegal sequence number)
// Remark
//	the field values of the gap descriptors filled would be of host-byte-order
//	return value may not exceed given capicity of the gaps buffer,
//	so the sequence number of the mostly expected packet might be calibrated to a value less than recvWindowNextSN
//	it is assumed that it is unnecessary to worry about atomicity of (recvWindowNextPos, recvWindowNextSN)
// Acknowledged are
//	[..., snExpect),
//	[snExpect + gapWidth[0], snExpect + gapWidth[0] + datalength[0]), 
//	[snExpect + gapWidth[0] + datalength[0] + gapWidth[1], snExpect + gapWidth[0] + datalength[0] + gapWidth[1] + datalength[1]) бнбн
int LOCALAPI ControlBlock::GetSelectiveNACK(seq_t & snExpect, FSP_SelectiveNACK::GapDescriptor * buf, int n) const
{
	if(n <= 0)
		return -EDOM;
	//
	int nRcv = CountReceived();	// gaps included, however
	if(nRcv <= 0)
	{
		snExpect = recvWindowNextSN;
		return 0;
	}
	//
	register int iHead = recvWindowNextPos - nRcv;
	if(iHead < 0)
		iHead += recvBufferBlockN;
	PFSP_SocketBuf p = HeadRecv() + iHead;
	// it is possible that the head packet is the gap because of delivery

	// To make life easier we have not taken into account of possibility of larger continuous data with much smaller gap
	// If a 'very large' gap or continuous received area appeared (exceed USHRT_MAX) it would be adjusted
	seq_t		seq0 = recvWindowNextSN - nRcv;	// Because of parallism it is not necessarily recvWindowFirstSN now
	uint32_t	dataLength;
	uint32_t	gapWidth;
	int			m = 0;
	for(buf[0].dataLength = 0; ; ++m)	// termination condition is embedded in the loop body
	{
		for(dataLength = 0; int(seq0 - recvWindowNextSN) < 0 && p->GetFlag<IS_FULFILLED>(); seq0++)
		{
			dataLength++;
			iHead++;
			if(iHead - recvBufferBlockN >= 0)
			{
				iHead = 0;
				p = HeadRecv();
			}
			else
			{
				p++;
			}
		}
		//
		// the gap
		for(gapWidth = 0; int(seq0 - recvWindowNextSN) < 0 && !p->GetFlag<IS_FULFILLED>(); seq0++)
		{
			gapWidth++;
			//
			iHead++;
			if(iHead - recvBufferBlockN >= 0)
			{
				iHead = 0;
				p = HeadRecv();
			}
			else
			{
				p++;
			}
		}
		//
		if(m == 0)
		{
			snExpect = seq0 - gapWidth;	// the accumulative acknowledgment
			buf[0].gapWidth = gapWidth;
			if(gapWidth == 0)
				break;
		}
		else if(m >= n || gapWidth == 0)
		{
			buf[m - 1].dataLength = dataLength;
			break;
		}
		else
		{
			buf[m].gapWidth = gapWidth;
			buf[m - 1].dataLength = dataLength;
		}
	}
	//
	return m;
}



// Slide the left border of the send window and mark the acknowledged buffer block free
void ControlBlock::SlideSendWindow()
{
	for(PFSP_SocketBuf p = HeadSend() + sendWindowHeadPos;
		int(sendWindowNextSN - sendWindowFirstSN) > 0 && p->GetFlag<IS_ACKNOWLEDGED>();
		sendWindowFirstSN++)
	{
		p->flags = 0;
		sendWindowSize--;
		//
		if(++sendWindowHeadPos >= sendBufferBlockN)
		{
			p = HeadSend();
			sendWindowHeadPos = 0;
		}
		else
		{
			p++;
		}
	}
}



// Given
//	ControlBlock::seq_t		the maximum sequence number expected by the remote end, without gaps
//	const GapDescriptor *	array of the gap descriptors
//	int						number of gap descriptors
// Do
//	Make acknowledgement, maybe accumulatively if number of gap descriptors is 0
// Return
//	the number of packets that are positively acknowledged
int LOCALAPI ControlBlock::DealWithSNACK(seq_t expectedSN, const FSP_SelectiveNACK::GapDescriptor *gaps, int n)
{
	// Check validity of the control block descriptors to prevent memory corruption propagation
	const int32_t & capacity = sendBufferBlockN;
	int32_t	iHead = sendWindowHeadPos;
	register seq_t seq0 = sendWindowFirstSN;
	int sentWidth = CountUnacknowledged();

	//
	PFSP_SocketBuf p = HeadSend() + iHead;
	int	countAck = 0;

	register int nAck = int(expectedSN - seq0);
	for(int	k = 0; ; k++)
	{
		// Make acknowledgement
		while(--nAck >= 0)
		{
			if(! p->GetFlag<IS_ACKNOWLEDGED>())
			{
				p->SetFlag<IS_ACKNOWLEDGED>();
				countAck++;
			}
			//
			if(++iHead - capacity >= 0)
			{
				iHead = 0;
				p = HeadSend();
			}
			else
			{
				p++;
			}
		}

		if(k >= n)
			break;
		//
		iHead += gaps[k].gapWidth;
		if(iHead - capacity >= 0)
			iHead -= capacity;
		p = HeadSend() + iHead;
		//
		nAck = gaps[k].dataLength;
	}

	return countAck;
}



// Return whether it is in the CLOSABLE state or a COMMIT packet has already been received
bool ControlBlock::IsClosable() const
{
	register int k = recvWindowHeadPos;
	register PFSP_SocketBuf skb = HeadRecv() + k;
	// Check the packet before COMMIT
	for (int i = 0; i < CountReceived() - 1; i++)
	{
		if (!skb->GetFlag<IS_FULFILLED>())
			return false;
		//
		if (++k - recvBufferBlockN >= 0)
		{
			k = 0;
			skb = HeadRecv();
		}
		else
		{
			skb++;
		}
	}
	// Check the last receive: it should be COMMIT
	return (skb->opCode == COMMIT);
}




// Given
//	seq_t	The sequence number of the packet that mostly expected by the remote end
//	unsigned int		The advertised size of the receive window, start from aforementioned most expected packet
// Return
//	Whether the given sequence number is legitimate
// Remark
//	If the given sequence number is legitimate, send window size of the near end is adjusted
//	See also SlideSendWindow()
bool LOCALAPI ControlBlock::ResizeSendWindow(seq_t seq1, unsigned int adRecvWin)
{
	// advertisement of an out-of order packet about the receive window size is simply ignored
	if(int32_t(seq1 - welcomedNextSNtoSend) <= 0)
		return true;
	welcomedNextSNtoSend = seq1;

	int32_t sentWidth = int32_t(sendWindowNextSN - sendWindowFirstSN);
	int32_t d = int(seq1 - sendWindowFirstSN);
	if(d > sentWidth)
		return false;	// you cannot acknowledge a packet not sent yet

	assert((uint64_t)sentWidth + adRecvWin < INT32_MAX);
	sendWindowSize = min(sendBufferBlockN, int32_t(d + adRecvWin));
	return true;
}



bool ControlBlock::FSP_SocketBuf::Lock()
{
#if ARCH_BIG_ENDIAN
	// we knew 'flags' is of type uint16_t
	return InterlockedBitTestAndSet((LONG *) & flags, EXCLUSIVE_LOCK + 16) == 0;
#else
	return InterlockedBitTestAndSet((LONG *) & flags, EXCLUSIVE_LOCK) == 0;
#endif
}




// Peek the packet rightly in front of COMMIT
ControlBlock::PFSP_SocketBuf ControlBlock::PeekAnteCommit() const
{
	register seq_t seq = sendWindowNextSN;
	register int d = int(seq - sendWindowFirstSN);
	register PFSP_SocketBuf skb;
	if (d < 0)
		return NULL;

	while (int(seq - sendBufferNextSN) < 0)
	{
		d += sendWindowHeadPos;
		//
		skb = HeadSend() + (d - sendBufferBlockN >= 0 ? d - sendBufferBlockN : d);
		if(skb->opCode == COMMIT)
		{
			if(seq + 1 - sendBufferNextSN >= 0)
				return NULL;
			d++;
			return HeadSend() + (d - sendBufferBlockN >= 0 ? d - sendBufferBlockN : d);
		}

		seq++;
		d = int(seq - sendWindowFirstSN);
	}
	//
	return NULL;
}
