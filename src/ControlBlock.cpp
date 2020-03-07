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
#include "FSP_Impl.h"

//
// Start Of Reflection
//
// Reflexing string representation of operation code, for debug purpose
const char * CStringizeOpCode::names[LARGEST_OP_CODE + 1] =
{
	"UNDEFINED/Shall not appear!",
	"INIT_CONNECT",
	"ACK_INIT_CONNECT",
	"CONNECT_REQUEST",
	"ACK_CONNECT_REQ",
	"RESET",
	"NULCOMMIT",	// Used to be ACK_START
	"PURE_DATA",	// Without any optional header
	"PERSIST",		// Alias: DATA_WITH_ACK
	"ACK_FLUSH",
	"RELEASE",
	"MULTIPLY",		// To clone connection, may piggyback payload
	"KEEP_ALIVE",
	"RESERVED_CODE13",
	"RESERVED_CODE14",
	"RESERVED_CODE15",
	//
	"PEER_SUBNETS",
	"SELECTIVE_NACK"
} ;



/**
	Reflecting string representation of FSP_Session_State and FSP_ServiceCode, for debug purpose
	Place here because value of the state or notice/service code is stored in the control block
 */
const char * CStringizeState::names[LARGEST_FSP_STATE + 1] =
{
	"NON_EXISTENT",
	// the passive listener to folk new connection handle:
	"LISTENING",
	// initiative, after sending initiator's check code, before getting responder's cookie
	// timeout to retry or NON_EXISTENT:
	"CONNECT_BOOTSTRAP",
	// after getting responder's cookie and sending formal CONNECT_REQUEST
	// before getting ACK_CONNECT_REQ, timeout to retry or NON_EXISTENT
	"CONNECT_AFFIRMING",
	// after getting legal CONNECT_REQUEST and sending back ACK_CONNECT_REQ
	// before getting ACK_START or first PERSIST. timeout to NON_EXISTENT:
	"CHALLENGING",
	// context cloned by MultiplyAndWrite or MultiplyAndGetSendBuffer:
	"CLONING",
	// after getting a non-EoT PERSIST
	"ESTABLISHED",
	// after sending FLUSH, before getting all packet-in-flight acknowledged
	"COMMITTING",
	// after getting all packet-in-flight acknowledged, including the FLUSH packet, without receiving peer's FLUSH
	"COMMITTED",
	// after receiving FLUSH
	"PEER_COMMIT",
	// after both receiving and sending FLUSH, before getting all packet-in-flight acknowledged
	"COMMITTING2",
	// after getting all packet-in-flight acknowledged and having received peer's FLUSH and the FLUSH is acknowledgeable
	"CLOSABLE",
	// passive close of connection
	"SHUT_REQUESTED",
	// asymmetric initiative shutdown
	"PRE_CLOSED",
	// after ULA shutdown the connection in CLOSABLE state gracefully
	// it isn't a pseudo-state alike TCP, but a physical, resumable/reusable state
	"CLOSED",
};


const char * CStringizeNotice::names[LARGEST_FSP_NOTICE + 1] =
{
	"NullNotice",
	// 1~7
	"FSP_NotifyListening",	// a reverse command to signal success execution of FSP_Listen
	"FSP_NotifyAccepting",	// a reverse command to make context ready
	"FSP_NotifyMultiplied",	// a reverse command to inform DLL to accept a multiply request
	"FSP_NotifyAccepted",
	"FSP_NotifyDataReady",
	"FSP_NotifyBufferReady",
	"FSP_NotifyToCommit",
	// 8~
	"FSP_NotifyFlushed",
	"FSP_NotifyToFinish",
	"FSP_NameResolutionFailed",
	"FSP_MemoryCorruption",
	"FSP_NotifyReset",
	"FSP_NotifyTimeout",
};



// Reflexing string representation of FSP_ServiceCode, for debug purpose
const char* CServiceCode::names[FSP_Shutdown + 1] =
{
	"NullCommand",
	"FSP_Listen",		// register a passive socket
	"InitConnection",	// register an initiative socket
	"FSP_Accept",		// accept the connection, make SCB of LLS synchronized with DLL 
	"FSP_Reset",		// a forward command, explicitly reject some request
	"FSP_Start/Urge",
	"FSP_Send",			// Here it is not a command to LLS, but as a context indicator to ULA
	"FSP_Receive",		// Here it is not a command to LLS, but as a context indicator to ULA
	"FSP_InstallKey",	// install the authenticated encryption key
	"FSP_Multiply",		// clone the connection, make SCB of LLS synchronized with DLL
	"FSP_Reset",		// a forward command, close the connection abruptly
	"FSP_Shutdown"
};



// assume it is atomic (the assumption might be broken!)
const char * CStringizeOpCode::operator[](int i)
{
	static char errmsg[] = "Unknown opCode: 0123467890123";
	if (i < 0 || i > LARGEST_OP_CODE)
	{
		snprintf(&errmsg[16], 14, "%d", i);
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
		snprintf(&errmsg[15], 14, "%d", i);
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
		snprintf(&errmsg[16], 14, "%d", i);
		return &errmsg[0];
	}
	return CStringizeNotice::names[i];
}


// String of the code
const char* CServiceCode::sof(int c)
{
	static char errmsg[] = "Unknown service: 0123467890123";
	if (c < 0 || c > FSP_Shutdown)
	{
		snprintf(&errmsg[17], 14, "%d", c);
		return &errmsg[0];
	}
	return CServiceCode::names[c];
}


CStringizeOpCode	opCodeStrings;
CStringizeState		stateNames;
CStringizeNotice	noticeNames;
//
// End Of Reflection
//



// Return
//	true if obtained the mutual-exclusive lock
//	false if timed out
// Remark
//	Exploit _InterlockedCompareExchange8 to keep memory access order as the coded order
bool CLightMutex::WaitSetMutex()
{
	uint64_t t0 = GetTickCount64();
	while (_InterlockedCompareExchange8(&mutex, 1, 0))
	{
		if (GetTickCount64() - t0 > MAX_LOCK_WAIT_ms)
		{
			BREAK_ON_DEBUG();
			return false;
		}
		//
		Sleep(TIMER_SLICE_ms);
	}
	return true;
}



// Given
//	PItemBackLog	pointe to the item to be pushed
// Return
//	non-negative on success, or negative on failure
// Remark
//	capacity must be some power of 2
int LLSBackLog::Put(const SItemBackLog& r)
{
	if (!WaitSetMutex())
		return -EDEADLK;

	if (count >= capacity)
	{
		SetMutexFree();
		return -ENOMEM;
	}

	register int i = tailQ;
	q[i] = r;
	tailQ = (i + 1) & (capacity - 1);

	count++;
	SetMutexFree();
	return i;
}



// Do
//	Remove the head log item in the queue
// Return
//	-EDEADLK if cannot obtain the lock
//	-ENOENT	if the queue is empty
//	non-negative on success
// Remark
//	capacity must be some power of 2
int LLSBackLog::Pop()
{
	if (!WaitSetMutex())
		return -EDEADLK;

	register int i = headQ;
	if(count == 0)
	{
		SetMutexFree();
		return -ENOENT;
	}

	headQ = (i + 1) & (capacity - 1);
	count--;

	SetMutexFree();
	return i;
}



// Given
//	const BackLogItem *		pointer to the backlog item to match
// Do
//	Search the backlog item that matches the given one. 'Match' means idRemote as well as salt of the two items are equal.
// Return
//	true if the given backlog item is matched with some item in the queue
//	false if no match found
PItemBackLog LLSBackLog::FindByRemoteId(ALFID_T idRemote, uint32_t salt)
{
	if (!WaitSetMutex())
		throw - EINTR;

	if(count <= 0)
	{
		SetMutexFree();
		return NULL;	// empty queue
	}

	// it is possible that phantom read occurred
	register int i = headQ;
	register int k = tailQ;
	do
	{
		if(q[i].idRemote == idRemote && q[i].salt == salt)
		{
			SetMutexFree();
			return &q[i];
		}
		i = (i + 1) & (capacity - 1);
	} while(i != k);
	//
	SetMutexFree();
	return NULL;
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
int LOCALAPI ControlBlock::Init(int32_t & sendSize, int32_t & recvSize) 
{
	memset(this, 0, sizeof(ControlBlock));
	backLog.capacity = FSP_BACKLOG_SIZE;

	recvBufferBlockN = recvSize / MAX_BLOCK_SIZE;
	sendBufferBlockN = sendSize / MAX_BLOCK_SIZE;
	if(recvBufferBlockN <= 0 || sendBufferBlockN <= 0)
		return -EINVAL;

	recvBufferBlockN = min(recvBufferBlockN, MAX_BUFFER_BLOCKS);
	sendBufferBlockN = min(sendBufferBlockN, MAX_BUFFER_BLOCKS);
	sendSize = MAX_BLOCK_SIZE * sendBufferBlockN;
	recvSize = MAX_BLOCK_SIZE * recvBufferBlockN;

	// safely assume the buffer blocks and the descriptor blocks of the send and receive queue are continuous
	int sizeDescriptors = sizeof(FSP_SocketBuf) * (recvBufferBlockN + sendBufferBlockN);

	// here we let it interleaved:
	// send buffer descriptors, receive buffer descriptors, receive buffer blocks and send buffer blocks
	// we're sure that FSP_SocketBuf itself is 64-bit aligned. to make buffer block 64-bit aligned
	_InterlockedExchange((PLONG)&sendBufDescriptors, (sizeof(ControlBlock) + 7) & 0xFFFFFFF8);
	_InterlockedExchange((PLONG)&recvBufDescriptors, sendBufDescriptors + sizeof(FSP_SocketBuf) * sendBufferBlockN);
	_InterlockedExchange((PLONG)&recvBuffer, (sendBufDescriptors + sizeDescriptors + 7) & 0xFFFFFFF8);
	_InterlockedExchange((PLONG)&sendBuffer, recvBuffer + recvBufferBlockN * MAX_BLOCK_SIZE);

	memset((octet *)this + sendBufDescriptors, 0, sizeDescriptors);

	return 0;
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

	register PFSP_SocketBuf p = HeadSend() + sendBufferNextPos;
	p->InitMarkLocked();
	p->ClearFlags();
	IncRoundSendBlockN(sendBufferNextPos);
	_InterlockedIncrement((PLONG)&sendBufferNextSN);

	return p;
}



// Given
//	int32_t *	[_Out_] placeholder of the size of the next free send buffer block
// Return
//	The start address of the next free send buffer block
// Remark
//	It is assumed that the caller have gain exclusive access on the control block among providers
octet * LOCALAPI ControlBlock::InquireSendBuf(int32_t *p_m)
{
	register int32_t k = LCKREAD(sendWindowHeadPos);
	register int32_t i = sendBufferNextPos;

	if(i == k && CountSendBuffered() != 0)
	{
		*p_m = 0;
		return NULL;
	}

	*p_m = ((i >= k ? sendBufferBlockN : k) - i) * MAX_BLOCK_SIZE;
	return (octet *)this + sendBuffer + i * MAX_BLOCK_SIZE;
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
//	assume that the caller eventually calls ReInitMarkComplete() before calling the function next time
ControlBlock::PFSP_SocketBuf LOCALAPI ControlBlock::AllocRecvBuf(seq_t seq1)
{
	if(int(seq1 - recvWindowExpectedSN) < 0)
		return NULL;	// an outdated packet received
	//
	if (int(seq1 - LCKREAD(recvWindowFirstSN) - recvBufferBlockN) >= 0)
		return NULL;	// a packet right to the right edge of the receive window may not be accepted

	register int32_t d = int32_t(seq1 - recvWindowNextSN);
	PFSP_SocketBuf p;
	if(d == 0)
	{
		p = HeadRecv() + recvWindowNextPos;
		IncRoundRecvBlockN(recvWindowNextPos);
		_InterlockedIncrement((PLONG)&recvWindowNextSN);
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
			_InterlockedExchange((PLONG)&recvWindowNextSN, seq1 + 1);
		}
		else if(p->IsComplete())
		{
			return p;	// this is an out-of-order packet and the payload buffer has been filled already
		}
	}
	//
	p->InitMarkLocked();
	p->ClearFlags();
	// Case 1: out-of-order packet received in a gap but it is not the left-edge of the gap
	if (seq1 != recvWindowExpectedSN)
		return p;

	// distance of the right edge of the receive window to the probable left edge of the first gap
	d = recvWindowNextSN - ++recvWindowExpectedSN;
	// Case 2: orderly delivery at the right-edge
	if (d <= 0)	// <? but it is safe
		return p;
	// now d is the maximum number of blocks that might be slided over

	// Case 3 out-of-order packet received in a gap and it is the left-edge of the gap
	// To slide left edge of the receive window
	register int32_t i = recvWindowNextPos - d;
	if (i < 0)
		i += recvBufferBlockN;
	// now i indexes the block with the new expectedSN
	// n1 is the number of blocks from the expected to the tail
	int n1 = recvBufferBlockN - i;
	// n2 is the number of blocks start from the head
	int n2 = d - n1;
	if (n2 < 0)
		n1 = d;
	register PFSP_SocketBuf q = HeadRecv() + i;
	i = 0;
	do
	{
		if (!q->IsComplete())
			return p;
		q++;
		recvWindowExpectedSN++;
	} while (++i < n1);
	//
	if (n2 <= 0)
		return p;
	//
	q = HeadRecv();
	i = 0;
	do
	{
		if (!q->IsComplete())
			return p;
		q++;
		recvWindowExpectedSN++;
	} while (++i < n2);
	//
	return p;
}



// Given
//	int32_t & : [_Out_] place holder of the number of bytes [to be] peeked.
//	int32_t & : [_Out_] place holder of the number of blocks peeked
//	bool & :	[_Out_] place holder of the End of Transaction flag
// Do
//	Peek the receive buffer, figure out not only the start address but also the length of the next message
//	till the end of receive buffer space, the last of the received packets, or the first buffer block
//	with the End of Transaction flag set, inclusively, whichever met first.
// Return
//	Start address of the received message
// Remark
//	However, it is not meant to be thoroughly idempotent in the sense that
//	receive buffers that have been inquired may not be delivered by ReadFrom
//	If the returned value is NULL, stored in int & [_Out_] is the error number
//	-EACCES		the buffer space is corrupted and unaccessible
//	-EPIPE		it is a compressed stream and ULA should receive in pipe mode
//	-EFAULT		the descriptor is corrupted (illegal payload length:
//				payload length of an intermediate packet of a message should be MAX_BLOCK_SIZE,
//				payload length of any packet should be no less than 0 and no greater than MAX_BLOCK_SIZE)
//	-EPERM		non-conforming to the protocol, shall be prohibited
octet* LOCALAPI ControlBlock::InquireRecvBuf(int32_t& nIO, int32_t& nBlock, bool& eotFlag)
{
	const int tail = recvWindowNextPos;
	register int i, m;
	eotFlag = false;
	if (tail > recvBufferBlockN)
	{
		nIO = -EACCES;	// -13
		return NULL;
	}

	nBlock = 0;
	nIO = 0;
	if (CountDeliverable() <= 0)
		return NULL;
	assert(int32_t(recvWindowNextSN - recvWindowFirstSN) > 0);

	PFSP_SocketBuf p = GetFirstReceived();
	if (p->GetFlag<Compressed>())
	{
		nIO = -EPIPE;	// -33
		return NULL;
	}

	octet* pMsg = GetRecvPtr(p);

	if (tail > recvWindowHeadPos)
		m = tail - recvWindowHeadPos;
	else
		m = recvBufferBlockN - recvWindowHeadPos;

#ifndef NDEBUG
	if (m == 0)
	{
		printf_s("\nShould not occur! When InquireRecvBuf recvWindowHeadPos has run to the right edge?\n");
		BREAK_ON_DEBUG();
		nIO = -EPERM;	// protocol implementation error
		return NULL;
	}
#endif
	//
	for (i = 0; i < m && p->IsComplete() && !p->IsDelivered(); i++)
	{
		if (p->len > MAX_BLOCK_SIZE || p->len < 0)
		{
			BREAK_ON_DEBUG();	// TRACE_HERE("Unrecoverable error! memory corruption might have occurred");
			nIO = -EFAULT;
			return NULL;
		}
		nIO += p->len;
		nBlock++;

		if (p->GetFlag<TransactionEnded>())
		{
			eotFlag = true;
			return pMsg;
		}
#ifndef NDEBUG
		if (p->opCode == PURE_DATA && p->len != MAX_BLOCK_SIZE)
		{
			// Unrecoverable error! Not conform to the protocol
			BREAK_ON_DEBUG();
			nIO = -EPERM;
			return NULL;
		}
#endif
		p++;
	}
	//
	return pMsg;
}



// Given
//	uint32_t			the number of blocks peeked and to be free
// Do
//	Free the packet buffer blocks that were marked as delivered by InquireRecvBuf
// Return
//	0 if no error occurred
//	negative on error:
//	-EPERM		non-conforming to the protocol, shall be prohibited
//	-EDOM		parameter error (nBlock is non-positive)
int LOCALAPI ControlBlock::MarkReceivedFree(int32_t nBlock)
{
	if (nBlock <= 0)
		return -EINVAL;

	register int32_t m = LCKREAD(recvWindowNextPos) - recvWindowHeadPos;
	if (m <= 0)
		m = recvBufferBlockN - recvWindowHeadPos;
	if (m < nBlock)
		return -EPERM;
	m = nBlock;

	PFSP_SocketBuf p = GetFirstReceived();
	for (register int32_t i = 0; i < m; p++, i++)
	{
		p->ReInitMarkDelivered();
	}
	// but preserve the packet flag for EoT detection, etc.
	AddRoundRecvBlockN(recvWindowHeadPos, m);
	_InterlockedExchangeAdd((PLONG)&recvWindowFirstSN, m);
	//^Memory barrier is mandatory
	return 0;
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
//	return value may not exceed given capacity of the gaps buffer,
//	so the sequence number of the mostly expected packet might be calibrated to a value less than recvWindowNextSN
//	it is assumed that it is unnecessary to worry about atomicity of (recvWindowNextPos, recvWindowNextSN)
// Acknowledged are
//	[..., snExpect),
//	[snExpect + gapWidth[0], snExpect + gapWidth[0] + dataLength[0]), 
//	[snExpect + gapWidth[0] + dataLength[0] + gapWidth[1], snExpect + gapWidth[0] + dataLength[0] + gapWidth[1] + dataLength[1]) ����
int LOCALAPI ControlBlock::GetSelectiveNACK(seq_t & snExpect, FSP_SelectiveNACK::GapDescriptor * buf, int n)
{
	if(n <= 0)
		return -EINVAL;

	int32_t nRcv = int32_t(recvWindowNextSN - recvWindowExpectedSN);	// most likely a gap only, however
	if (nRcv < 0)
		return -EFAULT;

	snExpect = recvWindowExpectedSN;	// the accumulative acknowledgement
	if (nRcv == 0)
		return 0;

	register int32_t i0 = recvWindowNextPos - nRcv;
	if(i0 < 0)
		i0 += recvBufferBlockN;
	PFSP_SocketBuf p = HeadRecv() + i0;
	seq_t seq0;

#define MovePointerToNextBlock()	\
	i0++;		\
	if (i0 - recvBufferBlockN >= 0)	\
	{			\
		i0 = 0;	\
		p = HeadRecv();				\
	}			\
	else p++
// end the macro definition

	uint32_t	dataLength;
	uint32_t	gapWidth;
	int			m = 0;
	seq0 = snExpect;
	while(m < n)
	{
		// the gap
		for(gapWidth = 0; int(seq0 - recvWindowNextSN) < 0 && !p->IsComplete(); seq0++)
		{
			gapWidth++;
			MovePointerToNextBlock();
		}
		// the data blocks
		for (dataLength = 0; int(seq0 - recvWindowNextSN) < 0 && p->IsComplete(); seq0++)
		{
			dataLength++;
			MovePointerToNextBlock();
		}
		//
		if (dataLength == 0 && gapWidth == 0)
			break;
		buf[m].dataLength = dataLength;
		buf[m].gapWidth = gapWidth;
		m++;
	}
	//
	return m;
}
#undef MovePointerToNextBlock



// Given
//	ControlBlock::seq_t		the sequence number that was accumulatively acknowledged
//	const GapDescriptor *	array of the gap descriptors
//	int						number of gap descriptors
// Do
//	Make acknowledgement, maybe accumulatively if number of gap descriptors is 0
// Return
//	-EAGAIN	if it is an outdated acknowledgement
//	the number of packets that are accumulatively acknowledged
// Remark
//	Delay sliding the send window till the caller requires the sliding
//	Assume integers in the gap descriptor have already been of host byte order
int LOCALAPI ControlBlock::DealWithSNACK(seq_t expectedSN, FSP_SelectiveNACK::GapDescriptor *gaps, int n)
{
	int	accumuAcks = int(expectedSN - sendWindowFirstSN);
	if (accumuAcks < 0)
		return -EAGAIN;

	int32_t	iHead = sendWindowHeadPos;
	AddRoundSendBlockN(iHead, accumuAcks);

	PFSP_SocketBuf p = HeadSend() + iHead;
	for(int	k = 0; k < n; k++)
	{
		register int32_t nAck = gaps[k].dataLength;
		//
		iHead += gaps[k].gapWidth;
		if (iHead - sendBufferBlockN >= 0)
		{
			iHead -= sendBufferBlockN;
			if (iHead - sendBufferBlockN >= 0)
				return -EPERM;	// failed to conform with the protocol
		}
		else if (iHead < 0)
		{
			return -EPERM;		// failed to conform with the protocol
		}
		p = HeadSend() + iHead;
		//
		// Make acknowledgement
		while (nAck-- > 0)
		{
			p->marks |= FSP_BUF_ACKED;	// might be redundant, but it is safe
			//
			if (++iHead - sendBufferBlockN >= 0)
			{
				iHead = 0;
				p = HeadSend();
			}
			else
			{
				p++;
			}
		}
	}

	return accumuAcks;
}



// Return
//	true if the last packet in the queue is a packet with EoT flag set
//	false if otherwise
bool ControlBlock::HasBeenCommitted()
{
	register int32_t d = int32_t(recvWindowExpectedSN - recvWindowNextSN); 	// there should be no gap
	if (d != 0)
		return false;

	d = int32_t(recvWindowNextSN) - LCKREAD(recvWindowFirstSN);
	if (d <= 0)
		return false;

	d = recvWindowNextPos - 1;
	if (d - recvBufferBlockN >= 0)
		d -= recvBufferBlockN;
	else if (d < 0)
		d += recvBufferBlockN;

	return (HeadRecv() + d)->GetFlag<TransactionEnded>();
}



#if defined(TRACE) && !defined(NDEBUG)
int ControlBlock::DumpSendRecvWindowInfo() const
{
	return printf_s("\tSend[head, tail] = [%d, %d], packets on flight = %d\n"
		"\tSN next to send = %u(@%d)\n"
		"\tRecv[head, tail] = [%d, %d]\n"
		"\tSN first received = %u, max expected = %u, deliverable width = %d\n"
		, sendWindowHeadPos, sendBufferNextPos, int(sendWindowNextSN - sendWindowFirstSN)
		, sendWindowNextSN, sendWindowNextPos
		, recvWindowHeadPos, recvWindowNextPos
		, recvWindowFirstSN, recvWindowExpectedSN, int(recvWindowNextSN - recvWindowFirstSN));
}

int ControlBlock::DumpRecvQueueInfo() const
{
	return printf_s("\tRecv[head, tail] = [%d, %d], right edge is %u\n"
		"\tSN first received = %u, max expected = %u\n"
		, recvWindowHeadPos, recvWindowNextPos, recvWindowNextSN
		, recvWindowFirstSN, recvWindowExpectedSN);
}
#endif
