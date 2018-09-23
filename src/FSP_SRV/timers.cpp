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


// let calling of Destroy() in the NON_EXISTENT state to do cleanup 
#define TIMED_OUT() \
		ReplaceTimer(DEINIT_WAIT_TIMEOUT_ms);	\
		Notify(FSP_NotifyTimeout);	\
		lowState = NON_EXISTENT;	\
		SetMutexFree();	\
		return


// Lock the session context if the process of upper layer application is still active
// Abort the FSP session if ULA is not active
// Return true if the session context is locked, false if not
bool CSocketItemEx::LockWithActiveULA()
{
	char c = _InterlockedCompareExchange8(& locked, 1, 0);
	if(IsProcessAlive())
		return (c == 0 || WaitUseMutex());
	//
	AbortLLS();
	locked = 0;
	return false;
}



// Main purpose is to send the mandatory low-frequence KEEP_ALIVE
/**
  But the transaction commit time-out is handled in DLL, i.e. in ULA's work set.
	{COMMITTING, COMMITTING2}-->NON_EXISTENT
 */
void CSocketItemEx::KeepAlive()
{
	// Unlike LockWithActiveULA(), here is lock without wait
	char c = _InterlockedCompareExchange8(&locked, 1, 0);
	if (!IsProcessAlive())	// assume it takes little time to detect process life
	{
		if (c == 0)
		{
			// If the time-out handler took the lock, it may abort the session safely
			AbortLLS();
		}
		else if(IsInUse())
		{
			inUse = 0;		// So that any WaitUseMutex() would be forcefully aborted
			ReplaceTimer(TIMER_SLICE_ms);
			// Assume there is no dead loop, eventually the socket would be unlocked
			// and the time-out handler would safely abort the session
		}
		// Or else it MUST be already in clean-up phase
		return;
	}

	// Whether it has been released elsewhere
	if (!IsInUse() || pControlBlock == NULL)
	{
		if (c == 0)
			SetMutexFree();
		return;
	}

	// If the lock could not be obtained this time, fire the timer a short while later
	if (c != 0)
	{
		if (timer != NULL)
			::ChangeTimerQueueTimer(TimerWheel::Singleton(), timer, TIMER_SLICE_ms, tKeepAlive_ms);
#if (TRACE & TRACE_HEARTBEAT)
		else
			REPORT_ERRMSG_ON_TRACE("It could have found orphan timer handler for lazy garbage collection");
		//
		if (pControlBlock != NULL)
			printf_s("\nFiber#%u's KeepAlive not executed due to lack of locks in state %s[%d]\n"
				, fidPair.source, stateNames[lowState], pControlBlock->state);
#endif
		return;
	}

	if (lowState == NON_EXISTENT)
	{
#if (TRACE & TRACE_HEARTBEAT)
		printf_s("\nFiber#%u's session control block is released in a delayed timer handler.\n", fidPair.source);
#endif
		Destroy();
		SetMutexFree();
		return;
	}

	// To suppress unnecessary KEEP_ALIVE
	bool keepAliveNeeded = _InterlockedExchange(&tLazyAck_us, 0) != 0;
	keepAliveNeeded = IsNearEndMoved() || keepAliveNeeded;
	if (keepAliveNeeded)
	{
		SendKeepAlive();	// No matter which state it is in
		keepAliveNeeded = false;
	}
	else if(mobileNoticeInFlight != 0)
	{
		keepAliveNeeded = true;
	}

	timestamp_t t1 = NowUTC();
	switch(lowState)
	{
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
		// EXPERIMENTAL: To suppress unnecessary KEEP_ALIVE
		if (lowState != PEER_COMMIT && lowState != COMMITTING2 && keepAliveNeeded)
			SendKeepAlive();
		break;
	// assert: TRANSIENT_STATE_TIMEOUT_ms < RECYCLABLE_TIMEOUT_ms && RECYCLABLE_TIMEOUT_ms < MAXIMUM_SESSION_LIFE_ms
	case PRE_CLOSED:
		if (t1 - tMigrate > (TRANSIENT_STATE_TIMEOUT_ms << 10))
		{
			// Automatically migrate to CLOSED state in TIME-WAIT state alike in TCP
			SetState(CLOSED);
			Notify(FSP_NotifyToFinish);
		}
	case CLOSED:
		if (t1 - tMigrate > (RECYCLABLE_TIMEOUT_ms << 10))
		{
#ifdef TRACE
			printf_s("\nTransient state time out in the %s state\n", stateNames[lowState]);
#endif
			TIMED_OUT();
		}
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
		// The shared memory portion of ControlBlock might be inaccessible.
#endif
		Destroy();
	}

	tLazyAck_us = 0;	// May be redundant, but it makes the code safe in the sense that next AddLazyAckTimer won't fail
	SetMutexFree();
}



// UNRESOLVED! TODO: Retransmission should be subjected to quota control/rate control
// Retransmission time-out handler
void CSocketItemEx::DoResend()
{
	if (pControlBlock->CountSendBuffered() <= 0)
	{
		HANDLE h = (HANDLE)InterlockedExchangePointer(&resendTimer, NULL);
		::DeleteTimerQueueTimer(TimerWheel::Singleton(), h, NULL);
		return;
	}

	if (!WaitUseMutex())
	{
#ifdef TRACE
		printf_s("\n#0x%X's DoResend not executed due to lack of locks in state %s. InUse: %d\n"
			, fidPair.source, stateNames[lowState], IsInUse());
#endif
		return;
	}

	// Because RemoveTimers() clear the isInUse flag before reset the handle resendTimer
	// we assert that resendTimer != NULL and pControlBlock != NULL
	// if the assertion failed, memory access exception might be raised.

	// To minimize waste of network bandwidth, try to resend packet that was not acknowledged but sent earliest
	int32_t				index1 = InterlockedOr((long *)&pControlBlock->sendWindowHeadPos, 0);
	const int32_t		N = pControlBlock->CountSentInFlight();
	timestamp_t			tNow = NowUTC();
	const int32_t		capacity = pControlBlock->sendBufferBlockN;

	register ControlBlock::PFSP_SocketBuf p = pControlBlock->HeadSend() + index1;
	register ControlBlock::seq_t seq1 = pControlBlock->sendWindowFirstSN;
	bool b = false;
	for (register int k = 0; k < N; k++)
	{
		// retransmission time-out is hard coded to 4RTT
		if ((tNow - p->timeSent) < ((uint64_t)tRoundTrip_us << 2))
		{
			if (!p->IsAcked())
				break;
#if defined(UNIT_TEST)
			printf_s("Packet #%u has been acknowledged already\n", seq1);
#endif
		}
		else if (!p->IsAcked())
		{
#if (TRACE & TRACE_HEARTBEAT)
			printf_s("Fiber#%u, to retransmit packet #%u\n", fidPair.source, seq1);
#endif
#ifndef UNIT_TEST
			if (EmitWithICC(p, seq1) <= 0)
				break;
#endif
			b = true;
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
	}

	// To further probe the receive window size if no packet was resent
	if (!b)
		EmitQ();

	SetMutexFree();
}



// Do
//	Send the KEEP_ALIVE packet, which support mobility, multi-home and selective negative acknowledgement
// Return
//	true if KEEP_ALIVE was sent successfully
//	false if send was failed
bool CSocketItemEx::SendKeepAlive()
{
	SKeepAliveCache & buf3 = keepAliveCache;	// a buffer with three headers

	memcpy(buf3.mp.subnets, savedPathsToNearEnd, sizeof(TSubnets));
	buf3.SetHostID(CLowerInterface::Singleton.addresses);
	buf3.mp.hs.Set(PEER_SUBNETS, sizeof(FSP_NormalPacketHeader));

	ControlBlock::seq_t	snKeepAliveExp;
	LONG len = GenerateSNACK(buf3.snack, snKeepAliveExp, sizeof(FSP_NormalPacketHeader) + sizeof(FSP_ConnectParam));
	if (len < 0)
	{
		printf_s("Fatal error %d encountered when generate SNACK\n", len);
		return false;
	}
#if (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
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
	SetIntegrityCheckCode(&buf3.hdr, NULL, 0, buf3.snack.GetSaltValue());
#if (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
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
//	The size of receive window MAY be less than the capacity of the queue because ULA might not accepted the data yet
// Return
//	true if the accumulative acknowledgement was sent successfully
//	false if send was failed
bool CSocketItemEx::SendAckFlush()
{
	struct
	{
		FSP_InternalFixedHeader	hdr;
		FSP_SelectiveNACK		snack;
	} ALIGN(MAC_ALIGNMENT) buf2;	// a buffer with two headers

	InterlockedIncrement(& nextOOBSN);
	buf2.snack.tLazyAck = htobe64(NowUTC() - tLastRecv);
	buf2.snack.serialNo = htobe32(nextOOBSN);
	buf2.snack.hs.Set(SELECTIVE_NACK, sizeof(buf2.hdr));

#if (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("Acknowledge flush: local fiber#%u, peer's fiber#%u\n\tAcknowledged seq#%u\n"
		, fidPair.source, fidPair.peer
		, pControlBlock->recvWindowNextSN);
#endif
	assert(pControlBlock->recvWindowExpectedSN == pControlBlock->recvWindowNextSN);
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
//	Milky payload might be retransmitted on demand, but it isn't implemented here
//  It is an accumulative acknowledgment if n == 0
//	Memory integrity is checked here as well
//	Side effect: the integer value in the gap descriptors are translated to host byte order here
int LOCALAPI CSocketItemEx::RespondToSNACK(ControlBlock::seq_t expectedSN, FSP_SelectiveNACK::GapDescriptor *gaps, int n)
{
	const ControlBlock::seq_t headSN = _InterlockedOr((LONG *)& pControlBlock->sendWindowFirstSN, 0);
	if(int(expectedSN - headSN) < 0)
		return -EDOM;
	if (int(expectedSN - pControlBlock->sendWindowLimitSN) > 0)
		return -EDOM;
	const int32_t capacity = pControlBlock->sendBufferBlockN;
	if (capacity <= 0
	 ||	sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * capacity > dwMemorySize)
	{
#ifdef TRACE
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

	const int	nAck = pControlBlock->DealWithSNACK(expectedSN, gaps, n);
#if (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("Accumulatively acknowledged SN = %u, %d packet(s) acknowledged.\n", expectedSN, nAck);
#endif
	if (nAck < 0)
	{
#ifdef TRACE
		printf_s("DealWithSNACK error, erro code: %d\n", nAck);
#endif
		return nAck;
	}

#if (TRACE & TRACE_HEARTBEAT)
	printf_s("Round trip time to calibrate = %u, packet(s) acknowledged = %d\n", tRoundTrip_us, nAck);
#endif
	if (nAck == 0)
		return nAck;

	// Sliding is possible as there is at least one packet acknowledged
	if (!pControlBlock->GetSendQueueHead()->IsAcked())
		return nAck;

	// Calibrate RTT ONLY if left edge of the send window is to be advanced
	// new = ((current + old) / 2 + old) / 2 = current/4 + old * 3/4
	if (gaps != NULL)
	{
		FSP_SelectiveNACK *pSNACK = (FSP_SelectiveNACK *)(void *)& gaps[n];
		uint64_t tDelay = be64toh(pSNACK->tLazyAck);
		//
		int32_t k = int32_t(expectedSN - headSN) - 1;
		assert(k >= 0);
		pControlBlock->AddRoundSendBlockN(k, pControlBlock->sendWindowHeadPos);
		if (k >= capacity)
			return -EACCES;	// memory access error!
		//
		uint64_t rtt64_us = NowUTC() - (pControlBlock->HeadSend() + k)->timeSent - tDelay;
		// If ever the peer cheats by giving the acknowledgment delay value larger than the real value
		// it would be eventually punished by a very large RTO!?
		// Do not bother to guess delay caused by near-end task-scheduling
		tRoundTrip_us = uint32_t(min((((rtt64_us + tRoundTrip_us) >> 1) + tRoundTrip_us) >> 1, UINT32_MAX));
#if (TRACE & TRACE_HEARTBEAT)
		printf_s("Round trip time calibrated: %u\n\tAcknowledgement delay: %llu\n", tRoundTrip_us, tDelay);
#endif
	}

	do
	{
		pControlBlock->SlideSendWindowByOne();
		if (pControlBlock->CountSentInFlight() <= 0)
			break;
	} while (pControlBlock->GetSendQueueHead()->IsAcked());

	// Only when the left edge of the send window is slided may payload-less packet with EoT set appended
	// It is assumed that if commit is pending the ULA would not manipulate the send queue
	if (_InterlockedExchange8(&shouldAppendCommit, 0) != 0)
	{
		pControlBlock->MarkSendQueueEOT();
		EmitQ();
	}

	return nAck;
}
