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



// Now it is the polling timer. Unlike LockWithActiveULA(), here the socket is locked without wait
void CSocketItemEx::KeepAlive()
{
	const char *c = (char *)_InterlockedCompareExchangePointer((void**)&lockedAt, (void*)__func__, 0);
	// assume it takes little time to detect process life
	if (!IsProcessAlive())
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

	if (!IsInUse())
	{
		if (c == 0)
			SetMutexFree();
		return;		// the socket has been released elsewhere
	}

	if (c != 0)
	{
#ifndef NDEBUG
		printf_s("\nFiber#%u's KeepAlive not executed,\n"
			"locked at %s in state %s[%d].\n"
			, fidPair.source
			, c, stateNames[lowState], lowState);
#endif
		return;
	}

	if (lowState == NON_EXISTENT)
	{
		assert(pControlBlock != NULL);
#if (TRACE & TRACE_HEARTBEAT)
		printf_s("\nFiber#%u's session control block is released in a delayed timer handler.\n", fidPair.source);
#endif
		if (pControlBlock->state >= ESTABLISHED)
			SendReset();
		Destroy();
		SetMutexFree();
		return;
	}

	timestamp_t t1 = NowUTC();
	switch(lowState)
	{
	case CONNECT_BOOTSTRAP:
	case CONNECT_AFFIRMING:
	case CHALLENGING:
	case CLONING:
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
		if(int64_t(t1 - SESSION_IDLE_TIMEOUT_us - tRecentSend) > 0
		&& int64_t(t1 - SESSION_IDLE_TIMEOUT_us - tLastRecv) > 0)
		{
#ifdef TRACE
			printf_s("\nSession idle time out in the %s state\n", stateNames[lowState]);
#endif
			TIMED_OUT();
		}
		DoEventLoop();
		break;
	case CLOSABLE:
		// CLOSABLE does NOT time out to CLOSED, and does NOT automatically recycled.
		DoEventLoop();
		break;
	case PRE_CLOSED:
		// Automatically migrate to CLOSED state in TIME-WAIT state alike in TCP
		if (t1 - tMigrate > (CLOSING_TIME_WAIT_ms * 1000))
		{
			ReplaceTimer(DEINIT_WAIT_TIMEOUT_ms);
			EmitStart();	// It shall be a RELEASE packet which is retransmitted at most once
			SetState(CLOSED);
		}	// ULA should have its own time-out clock enabled
		DoEventLoop();
		break;
	case CLOSED:
		if (int64_t(t1 - tMigrate + 1024 - (UINT32_MAX << 10)) < 0)
			ReplaceTimer(uint32_t((t1 - tMigrate) >> 10) + 1);
		//^exponentially back off;  the socket is subjected to be recycled in LRU manner
		DoEventLoop();
		break;
	default:
#ifndef NDEBUG
		printf_s("\n*** Implementation may not add state arbitrarily %s(%d)! ***\n", stateNames[lowState], lowState);
		// The shared memory portion of ControlBlock might be inaccessible.
#endif
		Destroy();
	}

	SetMutexFree();
}


// Given
//	int64_t		the round trip time of the packet due
// Do
//	Update the smoothed RTT
// TODO: refresh the RTT of the bundle path [source net-prefix][target net-prefix][traffic class]
//	for sake of congestion management
// The caller must make sure that the control block shared between LLS and DLL is available
void CSocketItemEx::UpdateRTT(int64_t rtt64_us)
{
	if (rtt64_us < 0)
		rtt64_us = UINT32_MAX;
	else if (rtt64_us == 0)
		rtt64_us = 1;
	// we donot set rtt64_us = UINT32_MAX else if(rtt64_us > UINT32_MAX), however.
	if (rtt64_us > COMMITTING_TIMEOUT_ms * 1000)
	{
		printf_s("New round trip time is ridiculously large: %lld\nSmoothed RTT is %u\n", rtt64_us, tRoundTrip_us);
		BREAK_ON_DEBUG();
	}
	//
	pControlBlock->perfCounts.PushJitter(rtt64_us - tRoundTrip_us);
	tRoundTrip_us = uint32_t(min((((rtt64_us + tRoundTrip_us) >> 1) + tRoundTrip_us) >> 1, UINT32_MAX));
}



// Do
//	Send the KEEP_ALIVE packet, which support mobility, multi-home and selective negative acknowledgement
// Return
//	true if KEEP_ALIVE was sent successfully
//	false if send was failed
bool CSocketItemEx::SendKeepAlive()
{
	if (lowState == PEER_COMMIT || lowState == COMMITTING2 || lowState >= CLOSABLE)
		return SendAckFlush();

	struct
	{
		FSP_InternalFixedHeader	hdr;
		FSP_ConnectParam		mp;
		FSP_PreparedKEEP_ALIVE	snack;
		void SetHostID(PSOCKADDR_IN6 ipi6) { mp.idListener = SOCKADDR_HOSTID(ipi6); }
	} buf3;

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

	pControlBlock->SignHeaderWith(&buf3.hdr, KEEP_ALIVE, (uint16_t)len
		, pControlBlock->sendWindowNextSN - 1
		, snKeepAliveExp);
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
// Remark
//	ACK_FLUSH is sent immediately when the last packet of the is received, where the delay shall be ignored
//	or resent as the heartbeat where the delay shall be ignored as well
bool CSocketItemEx::SendAckFlush()
{
#define buf2 cacheAckFlush
	//if (savedAckedSN == pControlBlock->recvWindowNextSN && savedSendSN == pControlBlock->sendWindowNextSN)
	//	return (SendPacket(1, ScatteredSendBuffers(&buf2, sizeof(buf2))) > 0);
	//savedAckedSN = pControlBlock->recvWindowNextSN;
	//savedSendSN = pControlBlock->sendWindowNextSN;

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
	pControlBlock->SignHeaderWith(&buf2.hdr, ACK_FLUSH, (uint16_t)sizeof(buf2)
		, pControlBlock->sendWindowNextSN - 1
		, pControlBlock->recvWindowNextSN
	);
	SetIntegrityCheckCode(&buf2.hdr, NULL, 0, buf2.snack.serialNo);
	return SendPacket(1, ScatteredSendBuffers(&buf2, sizeof(buf2))) > 0;
#undef buf2
}



// Given
//	ControlBlock::seq_t		the accumulatively acknowledged sequence number
//	GapDescriptor *			array of the gap descriptors
//	int						number of gap descriptors
// Do
//	Make acknowledgement, maybe accumulatively if number of gap descriptors is 0
//	And do retransmission if necessary
// Return
//  -EBADF	if gap description insane
//	-EDOM	if parameter error
//	-EFAULT if memory corrupted
//	>=0		the number of packets accumulatively acknowledged
// Remark
//	Milky payload might be retransmitted on demand, but it isn't implemented here
//  It is an accumulative acknowledgement if n == 0
//	Memory integrity is checked here as well
//	Side effect: the integer value in the gap descriptors are translated to host byte order here
int LOCALAPI CSocketItemEx::AcceptSNACK(ControlBlock::seq_t expectedSN, FSP_SelectiveNACK::GapDescriptor *gaps, int n)
{
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

	// Note that the returned value is the number of packets accumulatively acknowledged
	const int32_t nAck = pControlBlock->DealWithSNACK(expectedSN, gaps, n);
	if (nAck < 0)
	{
#ifdef TRACE
		printf_s("DealWithSNACK error, erro code: %d\n", nAck);
#endif
		return nAck;
	}

	if (nAck == 0)
		return nAck;

	pControlBlock->AddRoundSendBlockN(pControlBlock->sendWindowHeadPos, nAck);
	InterlockedExchange((LONG *)&pControlBlock->sendWindowFirstSN, expectedSN);

	return nAck;
}



// Assume it has got the mutex
// 1. Resend one packet (if any)
// 2. Send a new packet (if any)
// 3. Delayed acknowledgement
void CSocketItemEx::DoEventLoop()
{
	// Only need to synchronize the state in the 'cache' and the real state once because TCB is locked
	_InterlockedExchange8((char *)& lowState, pControlBlock->state);
	if (lowState <= NON_EXISTENT || lowState > LARGEST_FSP_STATE)
	{
		Destroy();
		return;
	}

	// Used to loop header of DoResend
	const int32_t	capacity = pControlBlock->sendBufferBlockN;
	int32_t			i1 = pControlBlock->sendWindowHeadPos;
	ControlBlock::seq_t seq1 = pControlBlock->sendWindowFirstSN;
	ControlBlock::PFSP_SocketBuf p = pControlBlock->HeadSend() + i1;

	timestamp_t		tNow = NowUTC();
	bool toStopResend = false;
	bool toStopEmitQ = false;

loop_start:
	// To minimize waste of network bandwidth, try to resend packet that was not acknowledged but sent earliest
	toStopResend = toStopResend || (int32_t(seq1 - pControlBlock->sendWindowNextSN) >= 0);
	if (!toStopResend)
	{
		// retransmission time-out is hard coded to 4RTT
		if ((tNow - p->timeSent) < ((uint64_t)tRoundTrip_us << 2))
		{
			if (!p->IsAcked())
			{
				toStopResend = true;
				goto l_step2;
			}
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
			{
				toStopResend = true;
				goto l_step2;
			}
#endif
			p->MarkResent();
			pControlBlock->perfCounts.countPacketSent++;
		}
#if defined(UNIT_TEST)
		else
			printf_s("Packet #%u has been acknowledged already\n", seq1);
#endif
		//
		++seq1;
		if (++i1 - capacity >= 0)
		{
			i1 = 0;
			p = pControlBlock->HeadSend();
		}
		else
		{
			p++;
		}
	}

l_step2:
	register ControlBlock::seq_t limitSN = pControlBlock->GetSendLimitSN();
	register ControlBlock::PFSP_SocketBuf skb;
	toStopEmitQ = toStopEmitQ || (int32_t(pControlBlock->sendWindowNextSN - limitSN) >= 0);
	// Used to be loop-body of EmitQ:
	if (!toStopEmitQ)
	{
		skb = pControlBlock->HeadSend() + pControlBlock->sendWindowNextPos;
		if (!skb->IsComplete() || skb->InSending())
		{
			toStopEmitQ = true;
			goto l_post_step3;	// ULA is still to fill the buffer
		}
#ifndef UNIT_TEST
		if (EmitWithICC(skb, pControlBlock->sendWindowNextSN) <= 0)
		{
			toStopEmitQ = true;
			goto l_post_step3;	// transmission failed
		}
#endif
		skb->MarkSent();
		pControlBlock->perfCounts.countPacketSent++;
		//
		if (++pControlBlock->sendWindowNextPos >= capacity)
			pControlBlock->sendWindowNextPos = 0;
		InterlockedIncrement(&pControlBlock->sendWindowNextSN);
	}
	else if (int32_t(LCKREAD(pControlBlock->sendBufferNextSN) - pControlBlock->sendWindowNextSN) > 0)
	{
		// Zero window probing; although there's some code redundancy it keeps clarity
		skb = pControlBlock->HeadSend() + pControlBlock->sendWindowNextPos;
		if (!skb->IsComplete() || skb->InSending())
			goto l_post_step3;	// ULA is still to fill the buffer
		//
		if (int32_t(pControlBlock->sendWindowNextSN - pControlBlock->sendWindowLimitSN) == 0)
		{
#ifndef UNIT_TEST
			if (EmitWithICC(skb, pControlBlock->sendWindowNextSN) <= 0)
				goto l_post_step3;	// transmission failed
#endif
			skb->MarkSent();
			tZeroWinProbe = tRecentSend;
			pControlBlock->perfCounts.countZWPsent++;
			pControlBlock->perfCounts.countPacketSent++;
			//
			if (++pControlBlock->sendWindowNextPos >= capacity)
				pControlBlock->sendWindowNextPos = 0;
			InterlockedIncrement(&pControlBlock->sendWindowNextSN);
		}
		// ZWP timeout is hard-coded to 32RTT, without exponential back-off
		// Retransmit the last packet for ZWP, to urge SNACK.
		else if (int32_t(pControlBlock->sendWindowNextSN - pControlBlock->sendWindowLimitSN) > 0
			&& int64_t(tNow - tZeroWinProbe) > ((tRoundTrip_us + 1) << 5))
		{
			EmitWithICC(skb, pControlBlock->sendWindowNextSN);
			tZeroWinProbe = tRecentSend;
			pControlBlock->perfCounts.countZWPresent++;
			pControlBlock->perfCounts.countPacketResent++;
		}
	}

l_post_step3:
	if (int64_t(NowUTC() - tNow - TIMER_SLICE_ms * 1000) >= 0)
		goto l_final;

	if (!toStopResend)
		goto loop_start;
	if (!toStopEmitQ)
		goto l_step2;

l_final:
	// Finally, (Really!) Lazy acknowledgement
	if (delayAckPending || IsNearEndMoved() || mobileNoticeInFlight)
	{
		SendKeepAlive();
		delayAckPending = 0;
	}
}
