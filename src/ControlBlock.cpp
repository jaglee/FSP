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

#define _CRT_RAND_S
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
	"ACK_CONNECT_REQUEST",
	"RESET",
	"PERSIST",		// Alias: KEEP_ALIVE, DATA_WITH_ACK,
	"PURE_DATA",	// Without any optional header
	"ADJOURN",
	"ACK_FLUSH",
	"RESTORE",		// RESUME or RESURRECT connection, may piggyback payload
	"FINISH",
	"MULTIPLY",		// To clone connection, may piggyback payload
	"KEEP_ALIVE",
	"RESERVED_CODE14",
	"RESERVED_CODE15",
	"RESERVED_CODE16",
	//
	"CONNECT_PARAM",
	"EPHEMERAL_KEY",
	"SELECTIVE_NACK"
} ;


// Reflexing string representation of FSP_Session_State and FSP_ServiceCode, for debug purpose
// Place here because value of the state or notice/servic code is stored in the control block
const char * CStringizeState::names[CLOSED + 1] =
{
	"NON_EXISTENT",
	// resurrect from CLOSED:
	"QUASI_ACTIVE",
	// context cloned by ConnectMU:
	"CLONING",
	// initiative, after sending initiator's check code, before getting responder's cookie
	// timeout to retry or NON_EXISTENT:
	"CONNECT_BOOTSTRAP",
	// the passiver listener to folk new connection handle:
	"LISTENING",
	// after getting legal CONNECT_REQUEST and sending back ACK_CONNECT_REQUEST
	// before getting first PERSIST. timeout to NON_EXISTENT:
	"CHALLENGING",
	// after getting responder's cookie and sending formal CONNECT_REQUEST
	// before getting ACK_CONNECT_REQUEST, timeout to retry or NON_EXISTENT
	"CONNECT_AFFIRMING",
	// initiator: after getting the ACK_CONNECT_REQUEST 
	// responder: after getting the first PERSIST
	// no default timeout. however, implementation could arbitrarily limit a session life
	"ESTABLISHED",
	// after sending FLUSH, before getting all packet-in-flight acknowledged.
	"PAUSING",
	// after getting all packet-in-flight acknowledged, including the FLUSH packet.
	"CLOSABLE",
	// after sending RESTORE, before RESTORE acknowledged
	"RESUMING",
	// after ULA shutdown the connection in CLOSABLE state gracefully
	// it isn't a pseudo-state alike TCP, but a physical, resumable/reusable state
	"CLOSED"
};

const char * CStringizeNotice::names[LARGEST_FSP_NOTICE + 1] =
{
	"NullCommand",
	// 1~15: DLL to LLS
	"FSP_Listen",		// register a passive socket
	"InitConnection",		// register an initiative socket
	"SynConnection",		// make SCB entry of the DLL and the LLS synchronized
	"FSP_Reject",
	"FSP_Timeout",		// 5, 'try later', used to be FSP_Preclose
	"FSP_Dispose",		// AKA Reset. dispose the socket. connection might be aborted
	"FSP_Send",			// send a packet/a group of packets
	"FSP_Shutdown",		// close the connection
	// 9-15, 7 reserved
	"Reserved9",
	"Reserved10",
	"Reserved11",
	"Reserved12",
	"Reserved13",
	"Reserved14",
	"Reserved15",
	// 16~23: LLS to DLL in the backlog
	"FSP_NotifyDataReady",
	"FSP_NotifyReset",
	"FSP_NotifyRecycled",
	"FSP_NotifyAdjourn",
	"FSP_NotifyFlushed",
	"FSP_NotifyBufferReady",
	"FSP_NotifyDisposed",
	//
	"FSP_IPC_CannotReturn",	// LLS cannot return to DLL for some reason
	// 24~31: near end error status
	"FSP_NotifyIOError",
	"FSP_NotifyOverflow",
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
	MAX_BACKLOG_SIZE = 1 << m;
	return MAX_BACKLOG_SIZE;
}


// Given
//	TLogItem	the item to be pushed
// Return
//	non-negative on success, or negative on failure
// Remark
//	MAX_BACKLOG_SIZE must be some power of 2
template<typename TLogItem>
int LOCALAPI TSingleProviderMultipleConsumerQ<TLogItem>::Push(const TLogItem *p)
{
	if(InterlockedIncrementAcquire(& nProvider) > 1)
	{
		InterlockedDecrementRelease(& nProvider);
		return -EBUSY;
	}
	if(count >= MAX_BACKLOG_SIZE || nProvider > 1)
	{
		InterlockedDecrementRelease(& nProvider);
		return -ENOMEM;
	}

	register int i = tailQ;
	q[i] = *p;
	tailQ = (i + 1) & (MAX_BACKLOG_SIZE - 1);

	count++;
	InterlockedDecrementRelease(& nProvider);
	return i;
}


// Given
//	TLogItem *		the place holder of store the value of the first item in the queue
// Return
//	non-negative on success, or negative on failure
// Remark
//	MAX_BACKLOG_SIZE must be some power of 2
//	It is assumed that there is only one producer(optimistic push) but may be multiple consumer(conservative pop)
template<typename TLogItem>
int LOCALAPI TSingleProviderMultipleConsumerQ<TLogItem>::Pop(TLogItem *p)
{
	while(_InterlockedCompareExchange8(& mutex
		, SHARED_BUSY
		, SHARED_FREE)
		!= SHARED_FREE)
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
	headQ = (i + 1) & (MAX_BACKLOG_SIZE - 1);
	count--;

l_bailout:
	_InterlockedExchange8(& mutex, SHARED_FREE);	// with memory barrier release semantics assumed
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
		i = (i + 1) & (backLog.MAX_BACKLOG_SIZE - 1);
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
	sendBufDescriptors = (sizeof(ControlBlock) + 7) & 0xFFFFFFF8;
	recvBufDescriptors = sendBufDescriptors + sizeof(FSP_SocketBuf) * sendBufferBlockN;
	recvBuffer = (sendBufDescriptors + sizeDescriptors + 7) & 0xFFFFFFF8;
	sendBuffer = recvBuffer + recvBufferBlockN * MAX_BLOCK_SIZE;

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


// UNRESOLVED! TODO: the third form of ControlBlock::Init()
// send and receive buffers are attached later, but descriptors are pre-allocated?
// NO! because it makes security check of memory mapping overwhelmly complicated, if not impossible at all



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
	p->ZeroFlags();
	if(sendBufferNextPos - sendBufferBlockN >= 0)
		sendBufferNextPos = 0;
	sendBufferNextSN++;

	return p;
}


// Given
//	int &
//		[_In_]  the minimum buffer size requested
//		[_Out_] the size of the next free send buffer block, no less than what is requested
// Return
//	The start address of the next free send buffer block
// Remark
//	It is assumed that the caller have gain exclusive access on the control block among providers
//	However, LLS may change (sendWindowHeadPos, sendWindowFirstSN) simultaneously, non-atomically
void * LOCALAPI ControlBlock::InquireSendBuf(int & m)
{
	if(m > sendBufferBlockN * MAX_BLOCK_SIZE)
		return NULL;
	//
	register int i = sendBufferNextPos;
	register int k = sendWindowHeadPos;
	register int n = (i >= k)
		? (sendBufferBlockN - i) * MAX_BLOCK_SIZE
		: (k - i) * MAX_BLOCK_SIZE;
	//
	if(n < m)
		return NULL;
	//
	m = n;
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
		p->version = THIS_FSP_VERSION;
		p->opCode = PURE_DATA;
		p->ZeroFlags();
		p->len = MAX_BLOCK_SIZE;
		p->SetFlag<TO_BE_CONTINUED>(true);
		p->SetFlag<IS_COMPLETED>();
		p++;
	}
	//
	p->version = THIS_FSP_VERSION;
	p->opCode = PURE_DATA;
	p->ZeroFlags();
	p->len = n - MAX_BLOCK_SIZE * m;
	p->SetFlag<TO_BE_CONTINUED>(toBeContinued && p->len == MAX_BLOCK_SIZE);
	p->SetFlag<IS_COMPLETED>();
	//
	sendBufferNextPos += m + 1;
	sendBufferNextSN += m + 1;
	// assert(sendBufferNextPos <= sendBufferBlockN);	// See also InquireSendBuf
	if(sendBufferNextPos - sendBufferBlockN >= 0)
		sendBufferNextPos -= sendBufferBlockN;
	return (m + 1);
}


// Return the descriptor of the last buffered packet in the send buffer, NULL if the send queue is empty
ControlBlock::PFSP_SocketBuf ControlBlock::GetLastBufferedSend()
{
	if(CountSendBuffered() < 0)
		return NULL;
	//
	const register int i = sendBufferNextPos - 1;
	return HeadSend() + (i < 0 ? sendBufferBlockN - 1 : i );
}





// Return
//	The send buffer block descriptor of the packet to send
// Remark
//	It is assumed that the caller knew there exists at least one packet in the queue
ControlBlock::PFSP_SocketBuf ControlBlock::PeekNextToSend() const
{
	register int d = int(sendWindowNextSN - sendWindowFirstSN);
	if (d < 0 || d > sendWindowSize)
		return NULL;
	if (int(sendWindowNextSN - sendBufferNextSN) >= 0)
		return NULL;

	d += sendWindowHeadPos;
	return HeadSend() + (d - sendBufferBlockN >= 0 ? d - sendBufferBlockN : d);
}


// Given
//	seq_t		the sequence number that is to be assigned to the new allocated packet buffer
// Do
//	Get a receive buffer block from the receive window and set the sequence number
// Return
//	The descriptor of the receive buffer block
// Remark
//	It is assumed that it is unnecessary to worry about atomicity of (receiveMaxExpected, recvWindowNextPos)
//  the caller should check and handle duplication of the received data packet
ControlBlock::PFSP_SocketBuf LOCALAPI ControlBlock::AllocRecvBuf(seq_t seq1)
{
	if(int(seq1 - recvWindowFirstSN) < 0)
		return NULL;	// an outdated packet received
	//
	int d = int(seq1 - receiveMaxExpected);
	if(d >= RecvWindowSize())
		return NULL;

	PFSP_SocketBuf p;
	if(d == 0)
	{
		p = HeadRecv() + recvWindowNextPos++;
		receiveMaxExpected++;
		if(recvWindowNextPos >= recvBufferBlockN)
			recvWindowNextPos = 0;
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
			receiveMaxExpected = seq1 + 1;
			recvWindowNextPos = d + 1 >= recvBufferBlockN ? 0 : d + 1;
		}
		else if(p->GetFlag<IS_COMPLETED>())
		{
			return p;	// this is an out-of-order packet and the payload buffer has been filled already
		}
	}
	//
	p->ZeroFlags();
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
	PFSP_SocketBuf p = FirstReceived();	// HeadRecv() + recvWindowHeadPos;
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
	for(i = 0; i < m && p->GetFlag<IS_COMPLETED>(); i++)
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
//	buf: place holder/start address to store the received message data
//	n: capacity of the buffer, in octets. should not exceed MAX_BLOCK_SIZE * recvBufferBlockN
// Return
//	positive integer: number of octets fetched from the receive buffer (not necessarily delivered)
//	0: no data available
//	-EPERM		the parameter value is not permited (illegal memory overlap detected)
//	-ENOMEM		buffer capacity is not large enough the hold the whole content of the last packet
//	-EFAULT		the descriptor is corrupted (illegal payload length:
//				payload length of an intermediate packet of a message should be MAX_BLOCK_SIZE,
//				payload length of any packet should be no less than 0 and no greater than MAX_BLOCK_SIZE)
// Remark
//	Automatically slide the receive window. See also SlideReceiveWindow()
//	Data fetched are not necessarily finished in the message,
//	nevertheless data would not be fetched across message border
int LOCALAPI ControlBlock::FetchReceived(void * context, fpDeliverData_t fp)
{
	int m = 0;	// note that left border of the receive window slided in the loop body
	for(PFSP_SocketBuf p = FirstReceived(); p->GetFlag<IS_COMPLETED>(); p = FirstReceived())
	{
		if(p->len > MAX_BLOCK_SIZE || p->len < 0)
			return -EFAULT;

		// decryption and/or decompression are carried out via IoC
		if(fp(context, GetRecvPtr(p), p->len) < 0)
			break;

		// Set flag in a manner that it would not be re-delivered even IS_DELIVERED flag is not checked
		p->SetFlag<IS_COMPLETED>(false);
		p->SetFlag<IS_DELIVERED>();
		m += p->len;

		// Slide the left border of the receive window firstly
		recvWindowFirstSN++;
		if(++recvWindowHeadPos - recvBufferBlockN >= 0)
			recvWindowHeadPos -= recvBufferBlockN;

		if(! p->GetFlag<TO_BE_CONTINUED>())
		{
			eomRecv = true;
			break;
		}
		// What? An imcomplete 'to be continued' intermediate packet received?
		if(p->len != MAX_BLOCK_SIZE)
			return -EFAULT;
	}
	//
	return m;
}



// Given
//	seq_t &			[_Out_]	the sequence number of the mostly expected packet
//	GapDescriptor *	output buffer of gap descriptors
//	int				capacity of the buffer, in number of GapDescriptors
// Return
//	positive integer: number of gaps found
//	0: no data available
//	-EDOM		input parameter error
//	-EFAULT		session control block is corrupted (e.g.illegal sequence number)
// Remark
//	the field values of the gap descriptors filled would be of host-byte-order
//	return value may not exceed given capicity of the gaps buffer,
//	so the sequence number of the mostly expected packet might be calibrated to a value less than receiveMaxExpected
//	it is assumed that it is unnecessary to worry about atomicity of (recvWindowNextPos, receiveMaxExpected)
int LOCALAPI ControlBlock::GetSelectiveNACK(seq_t & snExpect, FSP_SelectiveNACK::GapDescriptor * buf, int n) const
{
	if(n <= 0)
		return -EDOM;
	//
	const seq_t	seq0 = recvWindowFirstSN;
	snExpect = receiveMaxExpected;
	if(int(snExpect - seq0) <= 0)
		return 0;
	//
	register int tail = recvWindowNextPos - 1;
	if(tail < 0)
		tail = recvBufferBlockN - 1;
	PFSP_SocketBuf p = HeadRecv() + tail;
	if(! p->GetFlag<IS_COMPLETED>())
		return -EFAULT;

	// To make life easier we have not taken into account of possibility of larger continuous data with much smaller gap
	// If a 'very large' gap or continuous received area appeared (exceed USHRT_MAX) it would be adjusted
	UINT32	dataLength;
	UINT32	gapWidth;
	int		m = 0;
	seq_t	seq1 = snExpect - 1;
	do
	{
		if(m >= n && allowedDelay > 0)
			break;	// overflow for milky payload: simply discard stale packets
		// the continuous received area
		dataLength = 0;
		do
		{
			dataLength++;
			seq1--;
			tail--;
			if(tail < 0)
			{
				tail += recvBufferBlockN;
				p = HeadRecv() + tail;
			}
			else
			{
				p--;
			}
			//
		} while(int(seq1 - seq0) >= 0 && p->GetFlag<IS_COMPLETED>());
		//
		if(int(seq1 - seq0) < 0)
			break;	// the first (and possibly the last) continuous receive area
		// the previous gap
		gapWidth = 0;
		do
		{
			gapWidth++;
			seq1--;
			tail--;
			if(tail < 0)
			{
				tail += recvBufferBlockN;
				p = HeadRecv() + tail;
			}
			else
			{
				p--;
			}
		} while(int(seq1 - seq0) >= 0 && ! p->GetFlag<IS_COMPLETED>());
		//
		if(dataLength > USHRT_MAX || gapWidth > USHRT_MAX)
		{
			snExpect = seq1 + 1;
			m = 0;
		}
		else
		{
			if(m >= n)  // && allowedDelay == 0 // overflow for wine-style payload
			{
				snExpect -= buf[0].dataLength;
				snExpect -= buf[0].gapWidth;
				m = n - 1;
				memmove(& buf[0], & buf[1], sizeof(buf[0]) * m);
			}
			buf[m].dataLength = (UINT16)dataLength;
			buf[m].gapWidth = (UINT16)gapWidth;			 
			m++;
		}
	} while(int(seq1 - seq0) >= 0);
	//
	return m;
}



// Slide the left border of the send window and mark the acknowledged buffer block free
void ControlBlock::SlideSendWindow()
{
	for(PFSP_SocketBuf p = HeadSend() + sendWindowHeadPos; p->GetFlag<IS_ACKNOWLEDGED>(); sendWindowFirstSN++)
	{
		// don't care len and seq
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



// For RESTORE, MULTIPLY or ACK_CONNECT_REQUEST the first packet received is a PERSIST command
// and very likely it has no piggybacked payload. Such a packet shall be skipped as soon as possible
void ControlBlock::SkipPurePersist()
{
	PFSP_SocketBuf skb = HeadRecv();
	if (skb->opCode != PERSIST)
	{
#ifdef TRACE
		TRACE_HERE("the caller should make sure the head packet is a PERSIST");
#endif
		return;
	}
	if (skb->len == 0)
	{
		recvWindowHeadPos++;
		recvWindowFirstSN++;
	}
}



// Return whether it is in the CLOSABLE state or an ADJOURN packet has already been received
bool ControlBlock::IsClosable()
{
	if(state == CLOSABLE)
		return true;
	//
	int m = int(receiveMaxExpected - recvWindowFirstSN);
	for(int d = 1; d <= m; d++)
	{
		register int i = recvWindowNextPos - d;
		PFSP_SocketBuf skb = HeadRecv() + (d < 0 ? recvBufferBlockN - 1 : d);
		if(skb->opCode == ADJOURN)
		{
#ifdef TRACE
			printf_s(" ADJOURN received at position displacement %d from the end of the receive queue\n", i);
#endif
			state = CLOSABLE;
			return true;
		}
	}
	return false;
}






// Given
//	seq_t	The sequence number of the packet that mostly expected by the remote end
//	unsigned int		The advertised size of the receive window, start from aforementioned most expected packet
// Return
//	Whether the given sequence number is legitimate
// Remark
//	If the given sequence number is legitimate, send window size of the near end is adjusted
bool LOCALAPI ControlBlock::ResizeSendWindow(seq_t seq1, unsigned int adRecvWin)
{
	// advertisement of an out-of order packet about the receive window size is simply ignored
	if(int32_t(seq1 - sendWindowExpectedSN) <= 0)
		return true;
	sendWindowExpectedSN = seq1;

	int32_t sentWidth = int32_t(sendWindowNextSN - sendWindowFirstSN);
	int32_t d = int(seq1 - sendWindowFirstSN);
	if(d > sentWidth)
		return false;	// you cannot acknowledge a packet not sent yet

	// See also SlideSendWindow() and SlideSendWindow1()
	assert((uint64_t)sentWidth + adRecvWin < INT32_MAX);
	sendWindowSize = min(sendBufferBlockN, int32_t(d + adRecvWin));
	return true;
}



bool ControlBlock::FSP_SocketBuf::MarkInSending()
{
#if VMAC_ARCH_BIG_ENDIAN
	// we knew 'flags' is of type uint16_t
	return InterlockedBitTestAndSet((LONG *) & flags, BIT_IN_SENDING + 16) == 0;
#else
	return InterlockedBitTestAndSet((LONG *) & flags, BIT_IN_SENDING) == 0;
#endif
}
