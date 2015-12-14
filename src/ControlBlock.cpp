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

#ifndef NDEBUG
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
	"FSP_Reject",		// a forward command, explicitly reject some request
	"FSP_Recycle",		// a forward command, connection might be aborted
	"FSP_Start",		// send a start packet such as MULTIPLY, PERSIST and transactional COMMIT
	"FSP_Send",			// send a packet/a group of packets
	"FSP_Urge",			// send a packet urgently, mean to urge COMMIT
	"FSP_Shutdown",		// close the connection
	"FSP_InstallKey",	// install the authenticated encryption key
	"FSP_Resurrect",	// Resurrect a closable/closed connection in the recyling cach
	// 12-15, 4 reserved
	"Reserved12",
	"Reserved13",
	"Reserved14",
	"Reserved15",
	// 16~23: LLS to DLL in the backlog
	//FSP_NotifyAccepting = SynConnection,	// a reverse command to make context ready
	//FSP_NotifyRecycled = FSP_Recycle,		// a reverse command to inform DLL to release resource passively
	"FSP_NotifyAccepted",
	"FSP_NotifyDataReady",
	"FSP_NotifyBufferReady",
	"FSP_NotifyReset",
	"FSP_NotifyFlushed",
	"FSP_NotifyFinish",
	"Reserved22",
	"Reserved23",
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
	if (i < 0 || i > LARGEST_FSP_STATE)
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


CStringizeOpCode	opCodeStrings;
CStringizeState		stateNames;
CStringizeNotice	noticeNames;

#endif



// Remark
//	There would be at least two item in the queue
int LLSBackLog::InitSize(int n)
{
	if(n <= 1)
		return 0;
	int m = 0;
	while((n >>= 1) > 0)
		m++;
	// assume memory has been zeroed
	capacity = 1 << m;
	mutex = 0;
	return capacity;
}



// Given
//	TLogItem	the item to be pushed
// Return
//	non-negative on success, or negative on failure
// Remark
//	capacity must be some power of 2
int LOCALAPI LLSBackLog::Put(const BackLogItem *p)
{
	WaitSetMutex();

	if(count >= capacity)
	{
		SetMutexFree();
		return -ENOMEM;
	}

	register int i = tailQ;
	q[i] = *p;
	tailQ = (i + 1) & (capacity - 1);

	count++;
	SetMutexFree();
	return i;
}



// Given
//	TLogItem *		the place holder of store the value of the first item in the queue
// Return
//	non-negative on success, or negative on failure
// Remark
//	capacity must be some power of 2
//	It is assumed that there is only one producer(optimistic push) but may be multiple consumer(conservative pop)
int LOCALAPI LLSBackLog::Pop(BackLogItem *p)
{
	WaitSetMutex();

	register int i = headQ;
	if(count == 0)
	{
		SetMutexFree();
		return -ENOENT;
	}

	*p = q[i];
	headQ = (i + 1) & (capacity - 1);
	count--;

	SetMutexFree();
	return i;
}



// Remark
//	It is assumed that there is only one producer(optimistic push) but may be multiple consumer(conservative pop)
//	here we rely on a conservative memory model to make sure q[i] is written before tailQ is set
//	UNRESOLVED!? disable certain compiler optimization, out-of-order execution may break the assumption
//	If provider lock could not be obtained it will return true ('collision found') instead of raising an 'EBUSY' exception
bool LOCALAPI LLSBackLog::Has(const BackLogItem *p)
{
	WaitSetMutex();

	if(count <= 0)
	{
		SetMutexFree();
		return false;	// empty queue
	}

	// it is possible that phantom read occurred
	register int i = headQ;
	register int k = tailQ;
	do
	{
		if(q[i].idRemote == p->idRemote && q[i].salt == p->salt)
		{
			SetMutexFree();
			return true;
		}
		i = (i + 1) & (capacity - 1);
	} while(i != k);
	//
	SetMutexFree();
	return false;
}



// Given
//	FSP_ServiceCode	the notice code, shall not be NullCommand(0)
// Return
//	0 if no error
//	negative if failed, most likely because of overflow
//	positive if with warning, most likely because of duplicate tail notice
// Remark
//	Duplicate tail notice is merged
//	NullCommand cannot be put
int LOCALAPI LLSNotice::Put(FSP_ServiceCode c)
{
	while(_InterlockedCompareExchange8(& mutex, 1, 0) != 0)
		Sleep(1);
	//
	register char *p = (char *) & q[FSP_MAX_NUM_NOTICE - 1];
	if(*p != NullCommand)
	{
		_InterlockedExchange8(& mutex, 0);
		return -ENOMEM;
	}

	if(c == NullCommand)
	{
		_InterlockedExchange8(& mutex, 0);
		return -EDOM;
	}

	--p;
	//
	do
	{
		if(*p == c)
		{
			_InterlockedExchange8(& mutex, 0);
			return EAGAIN;
		}
	} while(*p == NullCommand && --p - (char *)q >= 0);
	_InterlockedExchange8(p + 1, c);
	//
	_InterlockedExchange8(& mutex, 0);
	return 0;
}



// Return the notice code on success, or NullCommand(0) on empty
// Remark
//	ULA should know that notices are out-of-band, emergent messages which might be processed out-of-order
FSP_ServiceCode LLSNotice::Pop()
{
	while(_InterlockedCompareExchange8(& mutex, 1, 0) != 0)
		Sleep(1);
	//
	register char *p = (char *) & q[FSP_MAX_NUM_NOTICE - 1];
	register char c = NullCommand;
	do
	{
		c = _InterlockedExchange8(p, c);
	} while(--p - (char *)q >= 0);
	//
	_InterlockedExchange8(& mutex, 0);
	return FSP_ServiceCode(c);
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
	_InterlockedExchange((LONG *) & sendBufDescriptors, (sizeof(ControlBlock) + 7) & 0xFFFFFFF8);
	_InterlockedExchange((LONG *) & recvBufDescriptors, sendBufDescriptors + sizeof(FSP_SocketBuf) * sendBufferBlockN);
	_InterlockedExchange((LONG *) & recvBuffer, (sendBufDescriptors + sizeDescriptors + 7) & 0xFFFFFFF8);
	_InterlockedExchange((LONG *) & sendBuffer, recvBuffer + recvBufferBlockN * MAX_BLOCK_SIZE);

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
	RoundSendBufferNextPos();
	p->InitFlags();	// and locked
	_InterlockedIncrement((LONG *) & sendBufferNextSN);

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
	register int32_t i = sendBufferNextPos;
	register int32_t k = _InterlockedCompareExchange((LONG *) & sendWindowHeadPos, 0, i);
	if(i == k)
	{
		sendWindowNextPos = sendBufferNextPos = 0;	// sendWindowHeadPos has been set to 0 
		m = MAX_BLOCK_SIZE * sendBufferBlockN;
		return (BYTE *)this + sendBuffer;
	}

	m = ((i > k ? sendBufferBlockN : k) - i) * MAX_BLOCK_SIZE;
	return (BYTE *)this + sendBuffer + i * MAX_BLOCK_SIZE;
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
		if(recvWindowNextPos - recvBufferBlockN >= 0)
			recvWindowNextPos -= recvBufferBlockN;
		_InterlockedIncrement((LONG *) & recvWindowNextSN);
	}
	else
	{
		bool ordered = (d > 0);
		d += recvWindowNextPos;
		if(d - recvBufferBlockN >= 0)
			d -= recvBufferBlockN;
		else if(d < 0)
			d += recvBufferBlockN;
		p = HeadRecv() + d;
		//
		if(ordered)
		{
			recvWindowNextPos = d + 1 >= recvBufferBlockN ? 0 : d + 1;
			_InterlockedExchange((LONG *) & recvWindowNextSN, seq1 + 1);
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
void * LOCALAPI ControlBlock::InquireRecvBuf(int & nIO, bool & toBeContinued)
{
	PFSP_SocketBuf p = GetFirstReceived();
	void * const pr = GetRecvPtr(p);	// the pointer value returned
	//
	const int tail = recvWindowNextPos;
	if(tail > recvBufferBlockN)
	{
		nIO = -EFAULT;
		return NULL;
	}

	register int i, m;
	if(tail < recvWindowHeadPos)
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
	while(CountSentInFlight() > 0)
	{
		register PFSP_SocketBuf p = GetSendQueueHead();
		if(! p->GetFlag<IS_ACKNOWLEDGED>())
			break;

		p->flags = 0;
		sendWindowSize--;

		if(++sendWindowHeadPos - sendBufferBlockN >= 0)
			sendWindowHeadPos -= sendBufferBlockN;
		//
		sendWindowFirstSN++;
	}

	if(int(sendWindowNextSN - sendWindowFirstSN) < 0)
	{
#ifdef TRACE
		printf_s("sendWindowNextSN(%u) out of sync on SlideSendWindow, set to %u\n", sendWindowNextSN, sendWindowFirstSN);
#endif
		sendWindowNextSN = sendWindowFirstSN;
		sendWindowNextPos = sendWindowHeadPos;
	}
}



// Normally synchronize sendWindowFirstSN with sendWindowNextSN is unnecessary but it does little harm
void ControlBlock::SlideSendWindowByOne()	// shall be atomic!
{
	if(++sendWindowHeadPos - sendBufferBlockN >= 0)
		sendWindowHeadPos -= sendBufferBlockN;
	_InterlockedIncrement((LONG *) & sendWindowFirstSN);
	//
	if(int(sendWindowNextSN - sendWindowFirstSN) < 0)
	{
#ifdef TRACE
		printf_s("sendWindowNextSN(%u) out of sync on SlideSendWindowByOne, set to %u\n", sendWindowNextSN, sendWindowFirstSN);
#endif
		sendWindowNextSN = sendWindowFirstSN;
		sendWindowNextPos = sendWindowHeadPos;
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
// Remark
//	As the receiver has nothing to know about the tail packets the sender MUST append a gap.
//	It's destructive! Endian conversion is also destructive.
//	UNRESOLVED!? For big endian architecture it is unnecessary to transform the descriptor: let's the compiler/optimizer handle it
int LOCALAPI ControlBlock::DealWithSNACK(seq_t expectedSN, FSP_SelectiveNACK::GapDescriptor *gaps, int & n)
{
	// Check validity of the control block descriptors to prevent memory corruption propagation
	const int32_t & capacity = sendBufferBlockN;
	int32_t	iHead = sendWindowHeadPos;
	register seq_t seq0 = sendWindowFirstSN;
	int sentWidth = CountSentInFlight();
	//
	PFSP_SocketBuf p = HeadSend() + iHead;
	int	countAck = 0;

	register int nAck = int(expectedSN - seq0);
	for(int	k = 0; ; k++)
	{
		seq0 += nAck;
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
		gaps[k].gapWidth = be32toh(gaps[k].gapWidth);
		seq0 += gaps[k].gapWidth;
		iHead += gaps[k].gapWidth;
		if(iHead - capacity >= 0)
			iHead -= capacity;
		p = HeadSend() + iHead;
		//
		nAck = gaps[k].dataLength = be32toh(gaps[k].dataLength);
	}

	// Here the SNACK suffix may be destroyed: the gapWidth overlay with 'serialNo' of the SNACK suffix
	// However the header signature is kept.
	if(int(sendWindowNextSN - seq0) > 0 && gaps != NULL)
	{
		gaps[n].gapWidth = int(sendWindowNextSN - seq0);
		n++;
	}

	return countAck;
}



// Return
//	0 if there is no COMMIT packet in the queue, or there is some gap before the COMMIT packet
//	positive if the last packet in the queue is a COMMIT and there is no gap before the COMMIT packet AND no packet after the COMMIT packet
//	negative if there is at least one COMMIT packet in the queue and there is no gap before the COMMIT packet but there is some packet after it as well
int ControlBlock::HasBeenCommitted() const
{
	register int k = recvWindowHeadPos;
	register PFSP_SocketBuf skb = HeadRecv() + k;
	int r = 0;
	int i;
	// Check the packet before COMMIT
	for(i = 0; i < CountReceived() - 1; i++)
	{
		if (!skb->GetFlag<IS_FULFILLED>())
			break;
		//
		if(skb->opCode == COMMIT)
			r++;
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
	//
	if(i == CountReceived() - 1 && skb->opCode == COMMIT)
		return r + 1;
	else
		return -r;
}



// Return
//	0 if there is no COMMIT packet at the tail and there is no error on appending one
//	1 if there is already an unsent COMMIT packet at the tail of the send queue
//	2 if there is already a COMMIT packet at the tail but it has been sent
//	-1 if failed
int ControlBlock::ReplaceSendQueueTailToCommit()
{
	register int i = sendBufferNextPos - 1;
	register int n = CountSendBuffered();
	register PFSP_SocketBuf p = HeadSend() + (i < 0 ? sendBufferBlockN - 1 : i);

	// make it idempotent, no matter whether last packet has been sent
	if(p->opCode == COMMIT)
	{
		if(n > 0 && p->Lock())
		{
			p->Unlock();
			return 1;
		}
		return 2;
	}

	if(n <= 0 || p->opCode != PURE_DATA || ! p->Lock())
	{
		p = GetSendBuf();
		if(p == NULL)
			return -1;
	}

	p->opCode = COMMIT;
	p->SetFlag<IS_COMPLETED>();
	p->Unlock();
	return 0;
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

	assert((uint64_t)CountSentInFlight() + adRecvWin < INT32_MAX);
	int32_t d = int(seq1 - sendWindowFirstSN);
	if(d > CountSentInFlight())
		return false;	// you cannot acknowledge a packet not sent yet

	SetSendWindowSize(int32_t(d + adRecvWin));
	return true;
}
