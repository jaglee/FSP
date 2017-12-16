/*
 * FSP lower-layer service program, software time-wheel, might be accelerated by hardware
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
#include "fsp_srv.h"
#include <assert.h>
#include <intrin.h>
#include <math.h>
#include <time.h>


//
// TODO: garbage collector, those whose parent process is inactive should be collected!
// Non-empty notice queue
// IsProcessAlive
//

// let calling of Destroy() in the NON_EXISTENT state to do cleanup 
#define TIMED_OUT() \
		ReplaceTimer(DEINIT_WAIT_TIMEOUT_ms);	\
		Notify(FSP_NotifyTimeout);	\
		lowState = NON_EXISTENT;	\
		SetMutexFree();	\
		return


// Main purpose is to send the mandatory low-frequence KEEP_ALIVE
/**
  [Idle Timeout]
	ACTIVE-->NON_EXISTENT
	PEER_COMMIT-->NON_EXISTENT
	COMMITTED-->NON_EXISTENT
	CLOSABLE-->NON_EXISTENT

  Retransmission time-out in CONNECT_BOOTSTRAP, CONNECT_AFFIRMING
  Transient state time-out in CHALLENGING, CLONING

  But the transaction commit time-out is handled in DLL, i.e. in ULA's work set.
	{COMMITTING, COMMITTING2}-->NON_EXISTENT
  So does the shutdown time-out:
	PRE_CLOSED-->NON_EXISTENT
 */
void CSocketItemEx::KeepAlive()
{
	if(! WaitUseMutex())
	{
#ifdef TRACE
		printf_s("\nFiber#%u's KeepAlive not executed due to lack of locks in state %s. InUse: %d\n"
			, fidPair.source, stateNames[lowState], IsInUse());
#endif
		if (lowState == NON_EXISTENT)
		{
			REPORT_ERRMSG_ON_TRACE("Lazy garbage collection found possible dead-lock");
			Destroy();
		}
		return;
	}

	if (!IsProcessAlive())
	{
		AbortLLS();		// shall pair with free-lock in one function!?
		SetMutexFree();
		return;
	}

	timestamp_t t1 = NowUTC();
	switch(lowState)
	{
	case NON_EXISTENT:
#ifdef TRACE
		printf_s("\nFiber#%u, SCB to be completely disposed\n", fidPair.source);
#endif
		if(pControlBlock != NULL)
		{
#ifdef TRACE
			printf_s("\tState of SCB used to be %s[%d]\n"
				, stateNames[pControlBlock->state], pControlBlock->state);
#endif
			pControlBlock->state = NON_EXISTENT;
		}
		Destroy();
		break;
	//
	case CONNECT_BOOTSTRAP:
	case CONNECT_AFFIRMING:
	case CHALLENGING:
		if (t1 - tMigrate > (TRANSIENT_STATE_TIMEOUT_ms << 10))
		{
#ifdef TRACE
			printf_s("\nTransient state time out in state %s\n", stateNames[lowState]);
#endif
			TIMED_OUT();
		}
		// CONNECT_BOOTSTRAP and CONNECT_AFFIRMING are counted into one transient period
		if(lowState != CHALLENGING)
			EmitStart();
		break;
	//
	case ESTABLISHED:
	case COMMITTING:
	case COMMITTED:
	case PEER_COMMIT:
	case COMMITTING2:
		if(t1 - tSessionBegin > (MAXIMUM_SESSION_LIFE_ms << 10))
		{
#ifdef TRACE
			printf_s("\nSession time out in the %s state\n", stateNames[lowState]);
#endif
			TIMED_OUT();
		}
		// If the peer has committed an ACK_FLUSH has accumulatively acknowledged it.
		// The near end needn't send periodical KEEP_ALIVE anymore
		if (lowState != PEER_COMMIT)
			SendKeepAlive();
		break;
	//
	case CLOSED:
		if ((t1 - tMigrate) > (RECYCLABLE_TIMEOUT_ms << 10))
		{
#ifdef TRACE
			printf_s("\nTransient state time out in the %s state\n", stateNames[lowState]);
#endif
			TIMED_OUT();
		}
	case PRE_CLOSED:
	case CLOSABLE:	// CLOSABLE does not automatically timeout to CLOSED
		if(t1 - tSessionBegin >  (MAXIMUM_SESSION_LIFE_ms << 10))
		{
			if(lowState != CLOSED)
				SendReset();	// See also RejectOrReset
			TIMED_OUT();
		}
		break;
	//
	case CLONING:
		if (t1 - tMigrate > (TRANSIENT_STATE_TIMEOUT_ms << 10)
		 || t1 - tSessionBegin >  (MAXIMUM_SESSION_LIFE_ms << 10) )
		{
#ifdef TRACE
			printf_s("\nTransient state time out or key out of life in the %s state\n", stateNames[lowState]);
#endif
			TIMED_OUT();
		}
		EmitStart();
		break;
	default:
#ifndef NDEBUG
		printf_s("\n*** ULA could not change state arbitrarily (%d) and beat the implementation! ***\n", lowState);
		// The shared memory portion of ControlBlock might be inaccessable.
#endif
		Destroy();
	}

	SetMutexFree();
}



// Retransmission time-out handler
void CSocketItemEx::DoResend()
{
	if (!WaitUseMutex())
	{
#ifdef TRACE
		printf_s("\n#0x%X's DoResend not executed due to lack of locks in state %s. InUse: %d\n"
			, fidPair.source, stateNames[lowState], IsInUse());
#endif
		return;
	}

	// In some risky situation DoResend may be triggered even after the resendTimer handle is set to NULL
	if (resendTimer == NULL)
		goto l_return;
	// assertion: if resendTimer != NULL then pControlBlock != NULL
	// if the assertion failed, memory access exception might be raised.

	const int32_t		capacity = pControlBlock->sendBufferBlockN;
	ControlBlock::seq_t seq1 = pControlBlock->sendWindowFirstSN;
	int32_t				index1 = pControlBlock->sendWindowHeadPos;
	ControlBlock::PFSP_SocketBuf p = pControlBlock->HeadSend() + index1;
	int32_t				n = pControlBlock->CountSentInFlight();
	timestamp_t			tNow = NowUTC();

	// SendKeepAlive would scan the receive buffer, which might be lengthy, and it might hold the lock too long time
	// So maximum buffer capacity should be limitted anyway
	if (shouldAppendCommit)
		SendKeepAlive();
	//^TODO: optimization: eliminate the long-interval KEEP_ALIVE, until short-interval KEEP_ALIVE is stopped

	SetMutexFree();
	//^Try to make it lockless

	ControlBlock::seq_t seqHead;
	register int	k;
	for (k = 0; k < n; k++)
	{
		if (!WaitUseMutex())
			break;

		if (resendTimer == NULL)
			goto l_return;

		// As a simultaneous ackowledgement may have slided the send window already, check the send window every time
		seqHead = _InterlockedOr((long *)&pControlBlock->sendWindowFirstSN, 0);
		if (int(seqHead - seq1) > 0)
		{
			k += seqHead - seq1;
			if (k >= n)
				break;
			seq1 = seqHead;
			//
			index1 = pControlBlock->sendWindowHeadPos;
			p = pControlBlock->HeadSend() + index1;
		}

		// retransmission time-out is hard coded to 4RTT
		if ((tNow - p->timeSent) < (tRoundTrip_us << 2))
		{
			SetMutexFree();
			break;
		}

		if (!p->GetFlag<IS_COMPLETED>())	// due to parallism the last 'gap' may include imcomplete buffered data
		{
#ifdef TRACE
			printf_s("Imcomplete packet: SN = %u, index position = %d\n", seq1, index1);
#endif
			SetMutexFree();
			break;
		}

		if (!p->GetFlag<IS_ACKNOWLEDGED>())
		{
#if defined(TRACE) && (TRACE & TRACE_HEARTBEAT)
			printf_s("Fiber#%u, to retransmit packet #%u\n", fidPair.source, seq1);
#endif
#ifndef UNIT_TEST
			if (EmitWithICC(p, seq1) <= 0)
			{
				SetMutexFree();
				break;
			}
#endif
		}
#if defined(UNIT_TEST)
		else
			printf_s("Packet #%u has been acknowledged already\n", seq1);
#endif
		//
		++seq1;
		if (++index1 - capacity >= 0)
		{
			index1 = 0;
			p = pControlBlock->HeadSend();
		}
		else
		{
			p++;
		}
		//
		SetMutexFree();
	}

	if (shouldAppendCommit)
		return;

	if (!WaitUseMutex())
		return;

	if (resendTimer == NULL)
		goto l_return;

	if(pControlBlock->CountSendBuffered() <= 0)
	{
		HANDLE h = (HANDLE)InterlockedExchangePointer(& resendTimer, NULL);
		::DeleteTimerQueueTimer(TimerWheel::Singleton(), h, NULL);
	}
	else
	{
		EmitQ();	// retry to send those pending on the queue
	}

l_return:
	SetMutexFree();
}



// The lazy selective negative acknowledgement time-out handler
void CSocketItemEx::LazilySendSNACK()
{
	lazyAckTimer = NULL;
	if(! WaitUseMutex())
	{
#ifdef TRACE
		printf_s("\n#0x%X's LazilySendSNACK not executed due to lack of locks in state %s. InUse: %d\n"
			, fidPair.source, stateNames[lowState], IsInUse());
#endif
		if(IsInUse() && lazyAckTimeoutRetryCount < TIMEOUT_RETRY_MAX_COUNT)
		{
			lazyAckTimeoutRetryCount++;
			AddLazyAckTimer();
		}
		return;
	}
	lazyAckTimeoutRetryCount = 0;

#ifdef TRACE
	if(!InState(ESTABLISHED) && !InState(COMMITTING) && !InState(COMMITTED))
		printf_s("\n#0x%X's LazilySendSNACK should not execute for it has migrated to state %s.\n"
			, fidPair.source, stateNames[lowState]);
#endif
	SendKeepAlive();
	SetMutexFree();
}



// Do
//	Send the KEEP_ALIVE packet, which support mobility, multi-home and selective negative acknowledgement
// Return
//	true if KEEP_ALIVE was sent successfully
//	false if send was failed
// TODO: suppress rate of sending KEEP_ALIVE
bool CSocketItemEx::SendKeepAlive()
{
	ALIGN(MAC_ALIGNMENT)
	struct
	{
		FSP_NormalPacketHeader	hdr;
		FSP_ConnectParam		mp;
		FSP_PreparedKEEP_ALIVE	snack;
	} buf3;	// a buffer with three headers
	FSP_ConnectParam &mp = buf3.mp;	// this alias make the code a little concise

	u_int k = CLowerInterface::Singleton.sdSet.fd_count;
	u_int j = 0;
	LONG w = CLowerInterface::Singleton.disableFlags;
	for (register u_int i = 0; i < k; i++)
	{
		if (!BitTest(&w, i))
		{
			mp.subnets[j++] = SOCKADDR_SUBNET(&CLowerInterface::Singleton.addresses[i]);
			if (j >= sizeof(mp.subnets) / sizeof(uint64_t))
				break;
		}
	}
	// temporarily there is no path to the local end:
	if (j <= 0)
		return false;
	//
	while (j < sizeof(mp.subnets) / sizeof(uint64_t))
	{
		mp.subnets[j] = mp.subnets[j - 1];
		j++;
	}
	//^Let's the compiler do loop-unrolling
	mp.idHost = SOCKADDR_HOSTID(&CLowerInterface::Singleton.addresses[0]);
	mp.hs.Set(PEER_SUBNETS, sizeof(FSP_NormalPacketHeader));

	ControlBlock::seq_t	snKeepAliveExp;
	LONG len = GenerateSNACK(buf3.snack, snKeepAliveExp, sizeof(FSP_NormalPacketHeader) + sizeof(FSP_ConnectParam));
	if (len < 0)
	{
		printf_s("Fatal error %d encountered when generate SNACK\n", len);
		return false;
	}
#if defined(TRACE) && (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("Keep-alive: local fiber#%u, peer's fiber#%u\n"
		"\tAcknowledged seq#%u, keep-alive header size = %d\n"
		, fidPair.source, fidPair.peer
		, snKeepAliveExp
		, len);
#endif

	buf3.hdr.Set(KEEP_ALIVE, (uint16_t)len
		, pControlBlock->sendWindowNextSN - 1
		, snKeepAliveExp
		, pControlBlock->AdRecvWS(pControlBlock->recvWindowNextSN - 1));
	//
	if (shouldAppendCommit)
		buf3.hdr.SetFlag<TransactionEnded>();
	//
	SetIntegrityCheckCode(&buf3.hdr, NULL, 0, buf3.snack.GetSaltValue());
#if defined(TRACE) && (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("To send KEEP_ALIVE seq #%u, acknowledge #%u\n\tsource ALFID = %u\n"
		, be32toh(buf3.hdr.sequenceNo)
		, snKeepAliveExp
		, fidPair.source);
	printf_s("KEEP_ALIVE total header length: %d, should be payloadless\n", len);
	DumpNetworkUInt16((uint16_t *)& buf3, len / 2);
#endif
	return SendPacket(1, ScatteredSendBuffers(&buf3, len)) > 0;
}



// Do
//	Send ACK_FLUSH
// Return
//	true if the accumulative acknowledgement was sent successfully
//	false if send was failed
bool CSocketItemEx::SendAckFlush()
{
	ALIGN(16)
	struct
	{
		FSP_NormalPacketHeader	hdr;
		FSP_SelectiveNACK		snack;
	} buf2;	// a buffer with two headers

	++nextOOBSN;
	buf2.snack.serialNo = htobe32(nextOOBSN);
	buf2.snack.hs.Set(SELECTIVE_NACK, sizeof(buf2.hdr));

#if defined(TRACE) && (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("Acknowledge flush: local fiber#%u, peer's fiber#%u\n\tAcknowledged seq#%u\n"
		, fidPair.source, fidPair.peer
		, pControlBlock->recvWindowNextSN);
#endif

	buf2.hdr.Set(ACK_FLUSH, (uint16_t)sizeof(buf2)
		, pControlBlock->sendWindowNextSN - 1
		, pControlBlock->recvWindowNextSN
		, pControlBlock->AdRecvWS(pControlBlock->recvWindowNextSN - 1));
	SetIntegrityCheckCode(&buf2.hdr, NULL, 0, buf2.snack.serialNo);
	return SendPacket(1, ScatteredSendBuffers(&buf2, sizeof(buf2))) > 0;
}



// Given
//	ControlBlock::seq_t		the accumulatedly acknowledged sequence number
//	GapDescriptor *			array of the gap descriptors
//	int						number of gap descriptors
// Do
//	Make acknowledgement, maybe accumulatively if number of gap descriptors is 0
//	And do retransmission if necessary
// Return
//  -EBADF	if gap description insane
//	-EDOM	if parameter error
//	-EFAULT if memory corrupted
//	>=0		the number of packets positively acknowledged
// Remark
//	Milky payload might be retansmitted on demand, but it isn't implemented here
//  It is an accumulative acknowledgment if n == 0
//	Memory integrity is checked here as well
//	Side effect: the integer value in the gap descriptors are translated to host byte order here
int LOCALAPI CSocketItemEx::RespondToSNACK(ControlBlock::seq_t expectedSN, FSP_SelectiveNACK::GapDescriptor *gaps, int n)
{
	const ControlBlock::seq_t headSN = pControlBlock->sendWindowFirstSN;
	if(int(expectedSN - headSN) < 0)
		return -EDOM;

	const int32_t capacity = pControlBlock->sendBufferBlockN;
	if (capacity <= 0
	 ||	sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * capacity > dwMemorySize)
	{
#if defined(TRACE)
		BREAK_ON_DEBUG();	//TRACE_HERE("memory overflow");
		printf_s("Given memory size: %d, wanted limit: %zd\n"
			, dwMemorySize
			, sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * capacity);
#endif
		return -EFAULT;
	}

	const int32_t sentWidth = pControlBlock->CountSentInFlight();
	if (sentWidth < 0)
	{
		BREAK_ON_DEBUG();	//TRACE_HERE("send queue internal state error");
		return -EFAULT;
	}
	if(sentWidth == 0)
		return 0;	// there is nothing to be acknowledged

	uint64_t	rtt64_us = NowUTC();
	const int	nAck = pControlBlock->DealWithSNACK(expectedSN, gaps, n, rtt64_us);
#if defined(TRACE) && (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("Accumulatively acknowledged SN = %u, %d packet(s) acknowledged.\n", expectedSN, nAck);
#endif
	if (nAck < 0)
	{
#ifdef TRACE
		printf_s("DealWithSNACK error, erro code: %d\n", nAck);
#endif
		return nAck;
	}

	// Note that the raw round trip time includes the lazy-acknowledgement delay
	// We hard-coded the lazy-acknowledgement delay as one RTT
	if(nAck > 0)
	{
		if (rtt64_us > LAZY_ACK_DELAY_MIN_ms * 2000)
			tRoundTrip_us = uint32_t((min(rtt64_us >> 1, UINT32_MAX) + tRoundTrip_us + 1) >> 1);
		else if (rtt64_us > LAZY_ACK_DELAY_MIN_ms * 1000)
			tRoundTrip_us = uint32_t((rtt64_us + tRoundTrip_us + 1) >> 1);
		else
			tRoundTrip_us = uint32_t((LAZY_ACK_DELAY_MIN_ms * 1000 + tRoundTrip_us + 1) >> 1);
	}

	// ONLY when the first packet in the send window is acknowledged may round-trip time re-calibrated
	// We assume that after sliding send window the number of unacknowledged was reduced
	if(pControlBlock->GetSendQueueHead()->GetFlag<IS_ACKNOWLEDGED>())
		pControlBlock->SlideSendWindow();

	return nAck;
}
