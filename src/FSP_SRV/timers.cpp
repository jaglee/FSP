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


// let calling of Destroy() in the NON_EXISTENT state to do cleanup 
#define TIMED_OUT() \
		ReplaceTimer(DEINIT_WAIT_TIMEOUT_ms);	\
		Notify(FSP_NotifyTimeout);	\
		lowState = NON_EXISTENT;	\
		SetMutexFree();	\
		return



// Now it is the polling timer. Unlike LockWithActiveULA(), here the socket is locked without wait
// TODO: recycle SHUT_REQUESTED or CLOSED socket in LRU manner
void CSocketItemEx::KeepAlive()
{
	const char *c = (char *)_InterlockedCompareExchangePointer((void**)&lockedAt, (void*)__FUNCTION__, 0);
	timestamp_t t1 = NowUTC();
	// assume it takes little time to get system clock
	while (t1 - tPreviousLifeDetection > (MAX_LOCK_WAIT_ms << 10))
	{
		if (IsProcessAlive())
		{
			tPreviousLifeDetection = t1;
			break;
		}
		if (c == 0)
		{
			// If the time-out handler took the lock, it may abort the session safely
			AbortLLS();
		}
		else if(IsInUse())
		{
			ClearInUse();
			//^So that any WaitUseMutex() would be forcefully aborted
			ReplaceTimer(TIMER_SLICE_ms);
			// Assume there is no dead loop, eventually the socket would be unlocked
			// and the time-out handler would safely abort the session
		}
		else
		{
			Destroy();	// The subroutine itself prevents double-entering
		}
		return;
	}

	callbackTimerPending = 0;
	if (!IsInUse())
	{
		if (c == 0)
			SetMutexFree();
		return;		// the socket has been released elsewhere
	}
	if (c != 0)
	{
		callbackTimerPending = 1;
		return;
	}

	// See also TIMEDOUT(); DEINIT_WAIT_TIMEOUT_ms
	if (lowState == NON_EXISTENT)
	{
		if (pControlBlock->state >= ESTABLISHED)
			SendReset();
		Destroy();
		SetMutexFree();
		return;
	}

	switch(lowState)
	{
	case CONNECT_BOOTSTRAP:
	case CONNECT_AFFIRMING:
	case CHALLENGING:
	case CLONING:
		if (t1 - tMigrate > (TRANSIENT_STATE_TIMEOUT_ms * 1000))
		{
#ifdef TRACE
			printf_s("\nTransient state time out in state %s\n", stateNames[lowState]);
#endif
			TIMED_OUT();
		}
		// CONNECT_BOOTSTRAP and CONNECT_AFFIRMING are counted into one transient period
		if (lowState != CHALLENGING)
		{
			EmitStart();
			ReplaceTimer(uint32_t((t1 - tMigrate) >> 10) + 1);
		}	// effectively exponentially back off
		break;
	//
	case ESTABLISHED:
	case COMMITTING:
	case COMMITTED:
	case PEER_COMMIT:
	case COMMITTING2:
		if (int64_t(t1 - SESSION_IDLE_TIMEOUT_us - tLastRecv) > 0)
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
	case SHUT_REQUESTED:
		// As if CLOSED, only might have to send lazy ACK_FLUSH. See also OnGetRelease()
		if (delayAckPending && SendAckFlush())
			delayAckPending = 0;
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
			ReplaceTimer(uint32_t((t1 - tMigrate) >> 10) + MAX_LOCK_WAIT_ms);
		//^exponentially back off;  the socket is subjected to be recycled in LRU manner
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
//	ControlBlock::seq_t		the sequence number of the packet that the acknowledgement delay was reported
//	uint32_t				the acknowledgement delay in microseconds (SHOULD be less than 200,000)
// Do
//	Update the smoothed RTT
// Remark
//	Implement a simple heuristic congestion management: delay-derived multiplicative decrease of send rate
//  The caller must make sure that the control block shared between LLS and DLL is available
//	This implementation does not support ultra-delay(sub-microsecond) network
/**
  Initially:
	SRTT <- R
	RTTVAR <- R/2
	RTO <- 1 second.

  Refreshing:
	RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
	SRTT <- (1 - alpha) * SRTT + alpha * R'
	RTO <- SRTT + max (G, K*RTTVAR)

	where K = 4.

	Whenever RTO is computed, if it is less than 1 second, then the RTO SHOULD be rounded up to 1 second.
	*/
void CSocketItemEx::UpdateRTT(ControlBlock::seq_t snAck, uint32_t tDelay)
{
	int32_t k = int32_t(snAck - pControlBlock->sendWindowFirstSN);
	if (k < 0 || k >= pControlBlock->sendBufferBlockN)
		return;

#if (TRACE & (TRACE_HEARTBEAT | TRACE_SLIDEWIN | TRACE_OUTBAND))
	printf_s("Round trip time to calibrate: %u\n\tacknowledgement delay: %u\n", tRoundTrip_us, tDelay);
#endif
	pControlBlock->AddRoundSendBlockN(k, pControlBlock->sendWindowHeadPos);
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend() + k;
	if ((skb->marks & (ControlBlock::FSP_BUF_SENT | ControlBlock::FSP_BUF_ACKED | ControlBlock::FSP_BUF_RESENT))
		!= ControlBlock::FSP_BUF_SENT)
	{
		return;
	}
	
	timestamp_t tNow = NowUTC();
	int64_t rtt64_us = int64_t(tNow - skb->timeSent - tDelay);
	if (rtt64_us < 0)
	{
		printf_s("Is the peer to cheat by report a ridiculously delay (%u)?\n"
			"Smoothed RTT is %u microseconds\n"
			"Adjusted latest packet delay is %" PRId64 "\n"
			, tDelay
			, tRoundTrip_us
			, rtt64_us);
		// BREAK_ON_DEBUG();
		return;
	}

	pControlBlock->perfCounts.PushJitter(rtt64_us - tRoundTrip_us);
	// Built-in rule: if current RTT exceeds smoothed RTT 'considerably' in 5 successive accumulative SNACKs,
	// assume congestion pending. 'Considerably' is 1 sigma
	// Selection of '5' depends on 'alpha' and 'beta' which are built-in as well.
	// However, the send rate is NOT decreased multiplicatively for sake of fairness against TFRC
	// Decrease rate is set considerably faster than increase rate although both change are linear.
	if (rtt64_us - tRoundTrip_us - rttVar_us > 0 && ++countRTTincreasement >= 5)
	{
		increaSlow = true;
		countRTTincreasement = 0;
		sendRate_Bpus = max(
			sendRate_Bpus - MAX_BLOCK_SIZE * 8 / double(tRoundTrip_us),
			MAX_BLOCK_SIZE * SLOW_START_WINDOW_SIZE / double(tRoundTrip_us)
		);
	}
	else if (rtt64_us - tRoundTrip_us + rttVar_us < 0)
	{
		countRTTincreasement = 0;
	}
	// If it happens to fell in the delta range, do not update the state
	//
	int64_t rttVar64_us = int64_t(rttVar_us) - (rttVar_us >> 2) + (abs(rtt64_us - tRoundTrip_us) >> 2);
	int64_t srtt64_us = tRoundTrip_us + ((rtt64_us - tRoundTrip_us) >> 3);
	tRTO_us = max(RETRANSMIT_MIN_TIMEOUT_us, uint32_t(srtt64_us + max(TIMER_SLICE_ms * 1000, rttVar64_us * 4)));
	tRTO_us = min(RETRANSMIT_MAX_TIMEOUT_us, tRTO_us);
	tRoundTrip_us = uint32_t(min(srtt64_us, UINT32_MAX));
	if (tRoundTrip_us == 0)
		tRoundTrip_us = 1;
	rttVar_us = uint32_t(min(rttVar64_us, UINT32_MAX));

	// A simple TCP-friendly AIMD congestion control in slow-start phase
	if (!increaSlow)
		sendRate_Bpus += double(int64_t(k + 1) * MAX_BLOCK_SIZE) / tRoundTrip_us;
#if (TRACE & TRACE_HEARTBEAT)
	fprintf(stderr, "%" PRId64 ", %u\n", tNow, tRoundTrip_us);
#endif
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

	FSP_KeepAliveExtension buf3;

	SetConnectParamPrefix(buf3.mp);
	buf3.SetHostID(CLowerInterface::Singleton.addresses);
	memcpy(buf3.mp.subnets, savedPathsToNearEnd, sizeof(TSubnets));

	_InterlockedIncrement(&nextOOBSN);	// Because lastOOBSN start from zero as well. See ValidateSNACK

	register int n = (sizeof(buf3.snack.gaps) - sizeof(buf3.mp)) / sizeof(FSP_SelectiveNACK::GapDescriptor);
	//^ keep the underlying IP packet from segmentation
	register FSP_SelectiveNACK::GapDescriptor* gaps = buf3.snack.gaps;
	ControlBlock::seq_t seq0;
	n = pControlBlock->GetSelectiveNACK(seq0, gaps, n);
	if (n < 0)
	{
#ifdef TRACE
		printf_s("GetSelectiveNACK return -0x%X\n", -n);
#endif
		return false;
	}
	// buf3.snack.nEntries = n;

	// Suffix the effective gap descriptors block with the FSP_SelectiveNACK
	// built-in rule: an optional header MUST be 64-bit aligned
	int len = int(sizeof(FSP_SelectiveNACK) + sizeof(buf3.snack.gaps[0]) * n);
	FSP_SelectiveNACK* pSNACK = &buf3.snack.sentinel;
	pSNACK->_h.opCode = SELECTIVE_NACK;
	pSNACK->_h.mark = 0;
	pSNACK->_h.length = htole16(uint16_t(len));
	pSNACK->ackSeqNo = htole32(seq0);
	pSNACK->latestSN = htole32(snLastRecv);
	pSNACK->tLazyAck = htole32(uint32_t(NowUTC() - tLastRecv));
#if BYTE_ORDER != LITTLE_ENDIAN
	while (--n >= 0)
	{
		gaps[n].dataLength = htole32(gaps[n].dataLength);
		gaps[n].gapWidth = htole32(gaps[n].gapWidth);
	}
#endif

	len += sizeof(buf3.mp);
	SignHeaderWith(&buf3.hdr, KEEP_ALIVE, (uint16_t)(len + sizeof(FSP_FixedHeader))
		, pControlBlock->sendWindowNextSN - 1
		, nextOOBSN);
	void* c = SetIntegrityCheckCode(&buf3.hdr, &buf3.mp, len, GetSalt(buf3.hdr));
	if (c == NULL)
		return false;
	memcpy(&buf3.mp, c, len);

	len += sizeof(FSP_FixedHeader);
#if (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("To send KEEP_ALIVE seq #%u, OOBSN#%u\n\tpeer's fiber#%u, source ALFID = %u\n"
		, be32toh(buf3.hdr.sequenceNo)
		, nextOOBSN
		, fidPair.peer
		, fidPair.source);
	printf_s("KEEP_ALIVE total header length: %d, should be payload-less\n", len);
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
	ALIGN(FSP_ALIGNMENT) struct SAckFlushCache buf2;

	_InterlockedIncrement(& nextOOBSN);
	buf2.snack._h.opCode = SELECTIVE_NACK;
	buf2.snack._h.mark = 0;
	buf2.snack._h.length = SNACK_HEADER_SIZE_LE16;
	buf2.snack.ackSeqNo = htole32(pControlBlock->recvWindowNextSN);
	buf2.snack.latestSN = htole32(snLastRecv);
	buf2.snack.tLazyAck = htole32(uint32_t(NowUTC() - tLastRecv));
#if (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("Acknowledge flush: local fiber#%u, peer's fiber#%u\n\tAcknowledged seq#%u\n"
		, fidPair.source, fidPair.peer
		, pControlBlock->recvWindowNextSN);
#endif
	// During development, in some curious data-race situation, the assertion may be failed:
	// assert(pControlBlock->recvWindowExpectedSN == pControlBlock->recvWindowNextSN);
#ifndef NDEBUG
	if (pControlBlock->recvWindowExpectedSN != pControlBlock->recvWindowNextSN)
		REPORT_ERRMSG_ON_TRACE("data race on setting recvWindowExpectedSN?");
#endif
	SignHeaderWith(&buf2.hdr, ACK_FLUSH, (uint16_t)sizeof(buf2)
		, pControlBlock->sendWindowNextSN - 1
		, nextOOBSN
	);
	void* c = SetIntegrityCheckCode(&buf2.hdr, &buf2.snack, sizeof(buf2.snack), GetSalt(buf2.hdr));
	if (c == NULL)
		return false;
	memcpy(&buf2.snack, c, sizeof(buf2.snack));
	return SendPacket(1, ScatteredSendBuffers(&buf2, sizeof(buf2))) > 0;
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
	 ||	sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * capacity > (u32)dwMemorySize)
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

#if BYTE_ORDER != LITTLE_ENDIAN
	for (register int32_t i = n - 1;  i >= 0; i++)
	{
		gaps[i].dataLength = htole32(gaps[n].dataLength);
		gaps[i].gapWidth = htole32(gaps[n].gapWidth);
	}
#endif
	// Note that the returned value is the number of packets accumulatively acknowledged
	const int32_t nAck = pControlBlock->DealWithSNACK(expectedSN, gaps, n);
	if (nAck < 0)
	{
#ifdef TRACE
		printf_s("DealWithSNACK error, error code: %d\n", nAck);
#endif
		return nAck;
	}

	if (nAck == 0)
		return nAck;

	pControlBlock->AddRoundSendBlockN(pControlBlock->sendWindowHeadPos, nAck);
	_InterlockedExchange((u32*)&pControlBlock->sendWindowFirstSN, expectedSN);

	return nAck;
}


/**
-  A packet is never retransmitted less than one RTO after the previous transmission of that packet.
-  Every time an in-band packet is sent (including a retransmission), if the timer is not running,
   start it running so that it will expire after RTO seconds (for the current value of RTO).
-  When all outstanding data has been acknowledged, turn off the retransmission timer.
-  When the retransmission timer expires, retransmit the packets that have not been acknowledged by the receiver,
   but limit the send rate by throttling mechanism.

-  Rate of retransmission MUST be throttled in a way that packet retransmission SHALL be subjected to congestion control as well.
-  However, at least one packet MAY be retransmitted in one clock interval,
   provide that the retransmission timer expires for the first packet that has not been acknowledged yet.

 */
//
// A simple quota-based AIMD congestion avoidance algorithm is implemenented here
//
// Assume it has got the mutex
// 1. Resend one packet (if any)
// 2. Send a new packet (if any)
// 3. Delayed acknowledgement
// TODO: UNRESOLVED! milky payload SHOULD never be resent?
void CSocketItemEx::DoEventLoop()
{
	// Only need to synchronize the state in the 'cache' and the real state once because TCB is locked
	_InterlockedExchange8((char*)& lowState, pControlBlock->state);
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
	ControlBlock::PFSP_SocketBuf skb;	// for send new packet.
	ControlBlock::seq_t limitSN = pControlBlock->GetSendLimitSN();
	timestamp_t		tNow = NowUTC();
	bool somePacketResent = false;
	bool toStopEmitQ = (int32_t(pControlBlock->sendWindowNextSN - limitSN) >= 0);
	bool toStopResend = (int32_t(seq1 - pControlBlock->sendWindowNextSN) >= 0);

	if (!toStopEmitQ || !toStopResend)
		quotaLeft += sendRate_Bpus * (tNow - tPreviousTimeSlot);

	// Additive increment of the send rate
	if (increaSlow)
		sendRate_Bpus += MAX_BLOCK_SIZE / double(max(tRoundTrip_us, TIMER_SLICE_ms * 1000));

loop_start:
	// To minimize waste of network bandwidth, try to resend packet that was not acknowledged but sent earliest
	if (!toStopResend)
	{
		if (int64_t(tNow - p->timeSent) - tRTO_us < 0)
		{
			if ((p->marks & (ControlBlock::FSP_BUF_ACKED | ControlBlock::FSP_BUF_RESENT)) == 0)
			{
				toStopResend = true;
				goto l_step2;
			}
#if defined(UNIT_TEST)
			printf_s("Packet #%u has been acknowledged already\n", seq1);
#endif
		}
		else if ((p->marks & ControlBlock::FSP_BUF_ACKED) == 0)
		{
#if (TRACE & TRACE_HEARTBEAT)
			printf_s("Fiber#%u, to retransmit packet #%u\n", fidPair.source, seq1);
#endif
#ifndef UNIT_TEST
			if (quotaLeft - (p->len + sizeof(FSP_NormalPacketHeader)) < 0)
				goto l_final;	// No quota left for send or resend
			if (EmitWithICC(p, seq1) <= 0)
				goto l_final;
			quotaLeft -= (p->len + sizeof(FSP_NormalPacketHeader));
			// For TCP-friendly congestion control, loss of packet means congestion encountered
			if (!somePacketResent && (p->marks & ControlBlock::FSP_BUF_RESENT) != 0
			 && pControlBlock->tfrc)	// TODO: detect ECN
			{
				sendRate_Bpus /= 2;
				quotaLeft /= 2;
				increaSlow = true;
			}
#endif
			somePacketResent = true;
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
	toStopResend = (int32_t(seq1 - pControlBlock->sendWindowNextSN) >= 0);
	
l_step2:
	// Used to be loop-body of EmitQ:
	if (!toStopEmitQ)
	{
		skb = pControlBlock->HeadSend() + pControlBlock->sendWindowNextPos;
		if (skb->MayNotSend())
		{
			toStopEmitQ = true;
			goto l_post_step3;	// ULA is still to fill the buffer
		}
#ifndef UNIT_TEST
		if (quotaLeft - (skb->len + sizeof(FSP_NormalPacketHeader)) < 0)
			goto l_final;	// No quota left for send or resend
		if (EmitWithICC(skb, pControlBlock->sendWindowNextSN) <= 0)
			goto l_final;
		quotaLeft -= (skb->len + sizeof(FSP_NormalPacketHeader));
#endif
		skb->MarkSent();
		pControlBlock->perfCounts.countPacketSent++;
		//
		if (++pControlBlock->sendWindowNextPos >= capacity)
			pControlBlock->sendWindowNextPos = 0;
		_InterlockedIncrement(&pControlBlock->sendWindowNextSN);
	}
	// Zero window probing; although there's some code redundancy it keeps clarity
	else if (pControlBlock->CountSentInFlight() == 0 && pControlBlock->CountSendBuffered() > 0)
	{
		skb = pControlBlock->HeadSend() + pControlBlock->sendWindowNextPos;
		if (skb->MayNotSend())
		{
			toStopEmitQ = true;
			goto l_post_step3;	// ULA is still to fill the buffer
		}
		//
#ifndef UNIT_TEST
		if (quotaLeft - (skb->len + sizeof(FSP_NormalPacketHeader)) < 0)
			goto l_final;	// No quota left for zero window probe
		if (EmitWithICC(skb, pControlBlock->sendWindowNextSN) <= 0)
			goto l_final;
		quotaLeft -= (skb->len + sizeof(FSP_NormalPacketHeader));
#endif
		pControlBlock->perfCounts.countZWPsent++;
		//
		skb->MarkSent();
		pControlBlock->perfCounts.countPacketSent++;
		//
		if (++pControlBlock->sendWindowNextPos >= capacity)
			pControlBlock->sendWindowNextPos = 0;
		_InterlockedIncrement(&pControlBlock->sendWindowNextSN);
	}
	// For sake of stability do not raise limitSN in this very clock click
	toStopEmitQ = (int32_t(pControlBlock->sendWindowNextSN - limitSN) >= 0);

l_post_step3:
	if (int64_t(NowUTC() - tNow - TIMER_SLICE_ms * 1000) >= 0)
		goto l_final;

	if (!toStopResend)
		goto loop_start;
	if (!toStopEmitQ)
		goto l_step2;

l_final:
	// Finally, (Really!) Lazy acknowledgement
	if ((delayAckPending || IsNearEndMoved() || mobileNoticeInFlight)
		&& SendKeepAlive())
	{
		delayAckPending = 0;
	}
	tPreviousTimeSlot = tNow;
}
/**
  When interface changed
	startedSlow = true.
	send_rate = (negotiated send rate!)(1 / 2 available, or quota - based)
 */
