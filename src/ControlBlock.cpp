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
	"PERSIST",		// Alias: DATA_WITH_ACK
	"PURE_DATA",	// Without any optional header
	"_COMMIT",
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
	Place here because value of the state or notice/servic code is stored in the control block
 */
const char * CStringizeState::names[LARGEST_FSP_STATE + 1] =
{
	"NON_EXISTENT",
	// the passiver listener to folk new connection handle:
	"LISTENING",
	// context cloned by MultiplyAndWrite or MultiplyAndGetSendBuffer:
	"CLONING",
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
};


const char * CStringizeNotice::names[LARGEST_FSP_NOTICE + 1] =
{
	"NullCommand",
	// 1~15: DLL to LLS
	"FSP_Listen",		// register a passive socket
	"InitConnection",	// register an initiative socket
	"FSP_Accept",		// accept the connection, make SCB of LLS synchronized with DLL
	"FSP_Reject",		// a forward command, explicitly reject some request
	"FSP_Recycle",		// a forward command, connection might be aborted
	"FSP_Start",		// send a packet starting a new send-transaction
	"FSP_Send",			// send a packet/a group of packets
	"FSP_Commit",		// commit a transmit transaction by send an EOT flag
	"FSP_Shutdown",		// close the connection
	"FSP_InstallKey",	// install the authenticated encryption key
	"FSP_Multiply",		// clone the connection, make SCB of LLS synchronized with DLL
	"FSP_AdRecvWindow",	// force to advertise the receive window ONCE by send a SNACK/ACK_FLUSH
	// 13-15, 3 reserved
	"Reserved13",
	"Reserved14",
	"Reserved15",
	// 16~23: LLS to DLL in the backlog
	//FSP_NotifyListening = FSP_Listen,		// a reverse command to signal success execution of FSP_Listen
	//FSP_NotifyAccepting = FSP_Accept,		// a reverse command to make context ready
	//FSP_NotifyRecycled = FSP_Recycle,		// a reverse command to inform DLL to release resource passively
	//FSP_NotifyMultiplied = FSP_Multiply,	// a reverse command to inform DLL to accept a multiply request
	"FSP_NotifyAccepted",
	"FSP_NotifyDataReady",
	"FSP_NotifyBufferReady",
	"FSP_NotifyToCommit",
	"FSP_NotifyFlushed",
	"FSP_NotifyToFinish",
	"FSP_NotifyReset",		// used to be FSP_Dispose or Reserved22
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
//
// End Of Reflection
//



// Given
//	int		intent capacity of the backlog. Should be no less than 2
// Do
//	Initialize the size/capacity, i.e. maximum number of entries of the backlog
// Return
//	The real capacity of the backlog. Trim the input value to the largest value of power of 2
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
	if (!WaitSetMutex())
		return -EINTR;

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



// Do
//	Remove the head log item in the queue
// Return
//	-EINTR	if internal panic arise
//	-ENOENT if the queue is empty
//	non-negative on success
// Remark
//	capacity must be some power of 2
int LLSBackLog::Pop()
{
	if (!WaitSetMutex())
		return -EINTR;

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
bool LOCALAPI LLSBackLog::Has(const BackLogItem *p)
{
	if (!WaitSetMutex())
		throw - EINTR;

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
//	position of new inserted notice, 0
//	negative if failed, most likely because of overflow
// Remark
//	Duplicate tail notice is merged, return FSP_MAX_NUM_NOTICE
//	NullCommand cannot be put
int LOCALAPI LLSNotice::Put(FSP_ServiceCode c)
{
	if (!WaitSetMutex())
		return -EINTR;
	//
	register char *p = (char *) & q[FSP_MAX_NUM_NOTICE - 1];
	if(*p != NullCommand)
	{
		SetMutexFree();
		return -ENOMEM;
	}

	if(c == NullCommand)
	{
		SetMutexFree();
		return -EDOM;
	}

	--p;
	//
	do
	{
		if(*p == c)
		{
			SetMutexFree();
			return FSP_MAX_NUM_NOTICE;
		}
	} while(*p == NullCommand && --p - (char *)q >= 0);
	_InterlockedExchange8(p + 1, c);
	//
	SetMutexFree();
	return int(p + 1 - (char *)q);
}



// Return the notice code on success, or NullCommand(0) on empty
// Remark
//	ULA should know that notices are out-of-band, emergent messages which might be processed out-of-order
FSP_ServiceCode LLSNotice::Pop()
{
	if (!WaitSetMutex())
		throw - EINTR;
	//
	register char *p = (char *) & q[FSP_MAX_NUM_NOTICE - 1];
	register char c = NullCommand;
	do
	{
		c = _InterlockedExchange8(p, c);
	} while(--p - (char *)q >= 0);
	//
	SetMutexFree();
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
int LOCALAPI ControlBlock::Init(int32_t & sendSize, int32_t & recvSize) 
{
	memset(this, 0, sizeof(ControlBlock));
	// notice01 = notice10 = NullCommand;
	backLog.InitSize();

	recvBufferBlockN = recvSize / MAX_BLOCK_SIZE;
	sendBufferBlockN = sendSize / MAX_BLOCK_SIZE;
	if(recvBufferBlockN <= 0 || sendBufferBlockN <= 0)
		return -EDOM;

	recvBufferBlockN = min(recvBufferBlockN, MAX_BUFFER_BLOCKS);
	sendBufferBlockN = min(sendBufferBlockN, MAX_BUFFER_BLOCKS);
	sendSize = MAX_BLOCK_SIZE * sendBufferBlockN;
	recvSize = MAX_BLOCK_SIZE * recvBufferBlockN;

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
void * LOCALAPI ControlBlock::InquireSendBuf(int *p_m)
{
	int & m = *p_m;
	if (m <= 0)
	{
		m = -EDOM;
		return NULL;
	}
	if((m - 1) / MAX_BLOCK_SIZE + 1 > (sendBufferBlockN - CountSendBuffered()))
	{
		int r = CountSendBuffered();
		BREAK_ON_DEBUG();
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
//	FSP_NormalPacketHeader*	the place-holder of sequence number and flags
//	ControlBlock::seq_t		the intent sequence number of the packet
// Do
//	Set the default sequence number, expected acknowledgment sequencenumber,
//	flags and the advertised receive window size field of the FSP header 
void LOCALAPI ControlBlock::SetSequenceFlags(FSP_NormalPacketHeader *pHdr, ControlBlock::seq_t seq1)
{
	pHdr->expectedSN = htobe32(recvWindowNextSN);
	pHdr->sequenceNo = htobe32(seq1);
	pHdr->ClearFlags();
	pHdr->SetRecvWS(AdRecvWS(recvWindowNextSN));
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
//	asssume that the caller eventually sets the IS_FULFILLED flag before calling the function next time
ControlBlock::PFSP_SocketBuf LOCALAPI ControlBlock::AllocRecvBuf(seq_t seq1)
{
	if(int(seq1 - recvWindowExpectedSN) < 0)
		return NULL;	// an outdated packet received
	//
	if(int(seq1 - recvWindowFirstSN - recvBufferBlockN) >= 0)
		return NULL;	// a packet right to the right edge of the receive window may not be accepted

	int d = int(seq1 - recvWindowNextSN);
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
	//
	d = int(recvWindowExpectedSN - recvWindowNextSN);
	PFSP_SocketBuf p2;
	do
	{
		d += recvWindowNextPos;
		if (d - recvBufferBlockN >= 0)
			d -= recvBufferBlockN;
		else if (d < 0)
			d += recvBufferBlockN;
		p2 = HeadRecv() + d;
		if(seq1 != recvWindowExpectedSN && ! p2->GetFlag<IS_FULFILLED>())
			break;
	} while ((d = int(++recvWindowExpectedSN - recvWindowNextSN)) < 0);
	//
	return p;
}



// Given
//	int & : [_Out_] place holder of the number of bytes [to be] peeked.
//	bool &: [_Out_] place holder of the End of Transaction flag
// Do
//	Peek the receive buffer, figure out not only the start address but also the length of the next message
//	till the end of receive buffer space, the last of the received packets, or the first buffer block
//	with the End of Transaction flag set, inclusively, whichever meets first.
// Return
//	Start address of the received message
// Remark
//	No receive buffer block is released
//	If the returned value is NULL, stored in int & [_Out_] is the error number
//	-EACCES		the buffer space is corrupted and unaccessible
//	-EFAULT		the descriptor is corrupted (illegal payload length:
//				payload length of an intermediate packet of a message should be MAX_BLOCK_SIZE,
//				payload length of any packet should be no less than 0 and no greater than MAX_BLOCK_SIZE)
//	-EAGAIN		some buffer block is double delivered, which breaks the protocol
//	-EPERM		imconformant to the protocol, which is prohibitted
void * LOCALAPI ControlBlock::InquireRecvBuf(int & nIO, bool & eotFlag)
{
	const int tail = recvWindowNextPos;
	eotFlag = false;
	if(tail > recvBufferBlockN)
	{
		nIO = -EACCES;	// -13
		return NULL;
	}

	PFSP_SocketBuf p = GetFirstReceived();
	void *pMsg = GetRecvPtr(p);
	nIO = 0;
	//
	register int i, m;
	if(tail > recvWindowHeadPos)
		m = tail - recvWindowHeadPos;
	else if(tail < recvWindowHeadPos || recvWindowNextSN != recvWindowFirstSN)
		m = recvBufferBlockN - recvWindowHeadPos;
	else 
		return pMsg;
	//
	if(m == 0) 
	{
#ifdef TRACE
		printf_s("\nOnly when both recvWindowHeadPos and recvWindowNextPos run to the right edge!\n");
#endif
		BREAK_ON_DEBUG();
		recvWindowHeadPos = recvWindowNextPos = 0;
		m = recvBufferBlockN;
		p = HeadRecv();
		pMsg = GetRecvPtr(p);
	}
	//
	for(i = 0; i < m && p->GetFlag<IS_FULFILLED>(); i++)
	{
		if(p->len > MAX_BLOCK_SIZE || p->len < 0)
		{
			BREAK_ON_DEBUG();	// TRACE_HERE("Unrecoverable error! memory corruption might have occurred");
			nIO = -EFAULT;
			return NULL;
		}
		//
		if (_InterlockedExchange8((char *) & p->opCode, 0) == 0)
		{
			BREAK_ON_DEBUG();	// TRACE_HERE("To double deliver a packet?");
			nIO = -EAGAIN;
			return NULL;
		}
		nIO += p->len;
		//
		if(p->GetFlag<TransactionEnded>())
		{
			eotFlag = true;
			i++;
			break;
		}
		if(p->len != MAX_BLOCK_SIZE)
		{
			BREAK_ON_DEBUG();	//TRACE_HERE("Unrecoverable error! Not conform to the protocol");
			nIO = -EPERM;
			return NULL;
		}
		//
		p++;
	}
	//
	return pMsg;
}



// Given
//	int			the number of bytes be free, shall equal the value passed out by InquireRecvBuf
// Do
//	Free the packet buffer blocks that cover at least the given number of bytes.
// Return
//	non-negative if number of blocks marked free
//	negative if error:
//	-EACCES		the buffer space is corrupted and unaccessible
//	-EFAULT		the descriptor is corrupted (illegal payload length:
//				payload length of an intermediate packet of a message should be MAX_BLOCK_SIZE,
//				payload length of any packet should be no less than 0 and no greater than MAX_BLOCK_SIZE)
//	-EINTR		the receive queue has been messed up
//	-EPERM		imconformant to the protocol, which is prohibitted
//	-EDOM		parameter error
int LOCALAPI ControlBlock::MarkReceivedFree(int nIO)
{
	const int tail = recvWindowNextPos;
	if (tail > recvBufferBlockN)
		return -EACCES;

	PFSP_SocketBuf p = GetFirstReceived();
	//
	register int i, m;
	m = nIO <= 0 ? 1 : (nIO - 1) / MAX_BLOCK_SIZE + 1;
	//
	for (i = 0; i < m && p->GetFlag<IS_FULFILLED>(); i++)
	{
		if (p->len > MAX_BLOCK_SIZE || p->len < 0)
			return -EFAULT;
		//
		if (p->opCode != 0)
			return -EINTR;
		//
		p->SetFlag<IS_FULFILLED>(false);	// release the buffer
		nIO -= p->len;
		//
		if (p->GetFlag<TransactionEnded>())
		{
			++i;
			break;
		}
		//
		if (p->len != MAX_BLOCK_SIZE)
			return -EPERM;
		//
		p++;
	}
	//
	if (nIO != 0 || i != m)
		return -EDOM;

	recvWindowFirstSN += i;
	recvWindowHeadPos += i;
	if (recvWindowHeadPos - recvBufferBlockN >= 0)
		recvWindowHeadPos -= recvBufferBlockN;

	return i;
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

	seq_t		seq0 = recvWindowNextSN - nRcv;	// Because of parallism it is not necessarily recvWindowFirstSN now
	uint32_t	dataLength;
	uint32_t	gapWidth;
	int			m = 0;
	do	// termination condition is embedded in the loop body
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
		if(m <= 0)
			snExpect = seq0 - gapWidth;	// the accumulative acknowledgment
		else
			buf[m - 1].dataLength = dataLength;
		//
		if(m >= n || gapWidth == 0)		// m is the number of gaps
			break;
		//
		buf[m++].gapWidth = gapWidth;
	} while (true);
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

		if(++sendWindowHeadPos - sendBufferBlockN >= 0)
			sendWindowHeadPos -= sendBufferBlockN;
		//
		sendWindowFirstSN++;
	}
}



// Given
//	ControlBlock::seq_t		the sequence number that was accumulatively acknowledged
//	const GapDescriptor *	array of the gap descriptors
//	int						number of gap descriptors
//	timestamp_t & [In, Out]	In: the timestamp of Now. Out: average round-robin time in microseconds, if some packet is acknowledged
// Do
//	Make acknowledgement, maybe accumulatively if number of gap descriptors is 0
// Return
//	the number of packets that are positively acknowledged
// Remark
//	As the receiver has nothing to know about the tail packets the sender MUST append a gap.
//	It's destructive! Endian conversion is also destructive.
//	UNRESOLVED!? For big endian architecture it is unnecessary to transform the descriptor: let's the compiler/optimizer handle it
int LOCALAPI ControlBlock::DealWithSNACK(seq_t expectedSN, FSP_SelectiveNACK::GapDescriptor *gaps, int n, timestamp_t & rttNow)
{
	// Check validity of the control block descriptors to prevent memory corruption propagation
	const int32_t & capacity = sendBufferBlockN;
	int32_t	iHead = sendWindowHeadPos;
	register seq_t	seq0 = sendWindowFirstSN;
	int32_t			sentWidth = CountSentInFlight();
	//
	PFSP_SocketBuf p = HeadSend() + iHead;
	int	countAck = 0;

	register int nAck = int(expectedSN - seq0);
	uint64_t rtt64_us = 0;
	for(int	k = 0; ; k++)
	{
		seq0 += nAck;
		// Make acknowledgement
		while(--nAck >= 0)
		{
			if(! p->GetFlag<IS_ACKNOWLEDGED>())
			{
				p->SetFlag<IS_ACKNOWLEDGED>();
				// round-trip time: 
				if(countAck++ == 0)
					rtt64_us = rttNow - p->timeSent;
				rtt64_us = (rtt64_us + (rttNow - p->timeSent)) >> 1;
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

	if(countAck > 0)
		rttNow = rtt64_us;

	return countAck;
}



// Return
//	true if the last packet in the queue is a _COMMIT and there is neither gap before _COMMIT nor after _COMMIT
//	false if there is no _COMMIT packet in the queue, or there is some gap before or after the _COMMIT packet
bool ControlBlock::HasBeenCommitted() const
{
	register int d = int(recvWindowExpectedSN - recvWindowNextSN);
	if (d != 0)
		return false;

	d = recvWindowNextPos - 1;
	if (d - recvBufferBlockN >= 0)
		d -= recvBufferBlockN;
	else if (d < 0)
		d += recvBufferBlockN;

	if ((HeadRecv() + d)->opCode != _COMMIT)
		return false;

	// Now scan the receive queue to found the gap. See also GetSelectiveNACK
	// Normally recvWindowExpectedSN == recvWindowNextSN if no gap, but...
#ifndef NDEBUG
	d = CountReceived();	// gaps included, however
	if (d <= 0)
		return true;
	//
	register int	iHead = recvWindowNextPos - d; 
	seq_t			seq0 = recvWindowNextSN - d;	// Because of parallism it is not necessarily recvWindowFirstSN now
	if (iHead < 0)
		iHead += recvBufferBlockN;
	// it is possible that the head packet is the gap because of delivery
	for (PFSP_SocketBuf	p = HeadRecv() + iHead; int(seq0 - recvWindowNextSN) < 0 && p->GetFlag<IS_FULFILLED>(); seq0++)
	{
		iHead++;
		if (iHead - recvBufferBlockN >= 0)
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
	if (int(seq0 - recvWindowNextSN) < 0)
	{
		BREAK_ON_DEBUG();
		return false;
	}
#endif
	return true;
}



// Return
//	0 if used to be no packet at all
//	1 if there existed a sent packet at the tail which has ready marked EOT 
//	2 if there existed an unsent packet at the tail and it is marked EOT
//  -1 if there existed a sent packet at the tail which could not be marked EOT
// See also @LLS::EmitQ()
int ControlBlock::MarkSendQueueEOT()
{
	if(CountSendBuffered() <= 0)
		return 0;

	register int i = sendBufferNextPos - 1;
	register PFSP_SocketBuf p;
	p = HeadSend() + (i < 0 ? sendBufferBlockN - 1 : i);

	if(p->GetFlag<IS_SENT>())
		return p->GetFlag<TransactionEnded>() ? 1 : -1;

	p->SetFlag<TransactionEnded>();
	p->SetFlag<IS_COMPLETED>();
	return 2;
}



// Given
//	seq_t			The sequence number of the packet that mostly expected by the remote end
//	unsigned int	The advertised size of the receive window, start from aforementioned most expected packet
// Return
//	Whether the given sequence number is legitimate
// Remark
//	If the given sequence number is legitimate, send window size of the near end is adjusted
//	advertisement of an out-of order packet about the receive window size is simply ignored
bool LOCALAPI ControlBlock::ResizeSendWindow(seq_t seq1, unsigned int adRecvWin)
{
	int32_t d = int(seq1 - sendWindowFirstSN);
	if (d < 0 || d > CountSentInFlight() || (uint64_t)CountSentInFlight() + adRecvWin >= INT32_MAX)
		return false;	// you cannot acknowledge a packet not sent yet
	
	if(int32_t(seq1 - welcomedNextSNtoSend) <= 0)
		return true;

	sendWindowLimitSN = seq1 + adRecvWin;
	welcomedNextSNtoSend = seq1;
	return true;
}


#if defined(TRACE) && !defined(NDEDUG)
int ControlBlock::DumpSendRecvWindowInfo() const
{
	return printf_s("\tSend[head, tail] = [%d, %d], packets on flight = %d\n"
		"\tSN next to send = %u(@%d), welcomedNextSNtoSend = %u\n"
		"\tRecv[head, tail] = [%d, %d], receive window size = %d\n"
		"\tSN first received = %u, max expected = %u\n"
		, sendWindowHeadPos, sendBufferNextPos, int(sendWindowNextSN - sendWindowFirstSN)
		, sendWindowNextSN, sendWindowNextPos, welcomedNextSNtoSend
		, recvWindowHeadPos, recvWindowNextPos, int(recvWindowNextSN - recvWindowFirstSN)
		, recvWindowFirstSN, recvWindowNextSN);
}
#endif
