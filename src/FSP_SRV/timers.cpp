/*
 * FSP lower-layer service program, software time-wheel, might be accelerated by hardware
 * heartbeat callback and its related functions to
 * - retransmit INITIATE_CONNECT, CONNECT_REQUEST, RESUME or MULTIPLY
 * - send heartbeat signal PERSIST
 * - idle timeout of CONNECT_BOOTSTRAP, CONNECT_AFFIRMING, QUASI_ACTIVE, CLONING
 *	 or CHALLENGING, as well as ACTIVE, RESUMING or COMMITTING state
 * - and finally, 'lazy' garbage collecting of CLOSABLE or CLOSED state
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
#include <math.h>
#include <time.h>

/**
  Continual KEEP_ALIVE packets are sent as heartbeat signals. PERSIST or COMMIT may be retransmitted in the heartbeat interval
  RELEASE may be retransmitted in the heartbeat interval as well
  ACK_CONNECT_REQ, PURE_DATA or ACK_FLUSH is retransmitted on demand.
  ACK_INIT_CONNECT is never retransmitted.

  Timeout is almost always notified to ULA
  
  [Transient State timeout]
	  {CONNECT_BOOTSTRAP, CHALLENGING, CONNECT_AFFIRMING}-->NON_EXISTENT
	  {COMMITTING, COMMITTING2, PRE_CLOSED}-->NON_EXISTENT
	  CLONING-->NON_EXISTENT
	  {RESUMING, QUASI_ACTIVE}-->CLOSED

  Implementation should start garbage collecting as soon as it switches into NON_EXSISTENT state.

  [Idle Timeout]
	  ACTIVE-->NON_EXISTENT
	  PEER_COMMIT-->NON_EXISTENT
	  COMMITTED-->NON_EXISTENT

  [Free Timeout]
	  CLOSED-->NON_EXISTENT

  Heartbeat_Interval_0 = RTT0 << 2
  RTT_N = Max(1, Average(persist_time - send_time) - Heartbeat_Interval_N)
  Heartbeat_Interval_(N+1) = Heartbeat_Interval_N  - (Heartbeat_Interval_N >> 2) + RTT_N
  The actual heartbeat interval should be no less than one OS time slice interval 
**/

// let calling of Extingush() in the NON_EXISTENT state to do cleanup 
#define TIMED_OUT() \
		Notify(FSP_NotifyTimeout);	\
		lowState = NON_EXISTENT;	\
		SetReady();	\
		return


// Timeout of initiation family retransmission, keep-alive transmission and Scanvenger activation
// State idle timeout
// A SCB in the CLOSABLE state could be RESUMEd while in the CLOSED state could be resurrected
void CSocketItemEx::TimeOut()
{
	if(! this->TestAndLockReady())
	{
#ifdef TRACE
		printf_s("\nTimeout not executed due to lack of locks in state %s. InUse: %d, IsReady: %d\n"
			, stateNames[lowState], IsInUse(), isReady);
#endif
		return;
	}

	timestamp_t t1 = NowUTC();
//#ifdef TRACE
//	TRACE_HERE(" it's time-outed");
//	DumpTimerInfo(t1);
//#endif
	switch(lowState)
	{
	case NON_EXISTENT:
		TRACE_HERE("After Extinguish() it needn't SetReady();");
		Extinguish();
		return;
	// Note that CONNECT_BOOTSTRAP and CONNECT_AFFIRMING are counted into one transient period
	case CONNECT_BOOTSTRAP:
	case CONNECT_AFFIRMING:
	case CHALLENGING:
		if (t1 - clockCheckPoint.tMigrate > (TRASIENT_STATE_TIMEOUT_ms << 10))
		{
#ifdef TRACE
			printf_s("\nTransient state time out in state %s\n", stateNames[lowState]);
#endif
			TIMED_OUT();
		}
		// TO BE TESTED...
		if(lowState != CHALLENGING)
			EmitStart();
		break;
	case ESTABLISHED:
		if(t1 - tLastRecv > (SCAVENGE_THRESHOLD_ms << 10))
		{
			ReplaceTimer(TRASIENT_STATE_TIMEOUT_ms);
			TIMED_OUT();
		}
	case COMMITTING:
	case COMMITTING2:
		if((t1 - clockCheckPoint.tMigrate) > (TRASIENT_STATE_TIMEOUT_ms << 10))
		{
#ifdef TRACE
			printf_s("\nTransient state time out in the %s state\n", stateNames[lowState]);
#endif
			TIMED_OUT();
		}
	case PEER_COMMIT:
	case COMMITTED:
		if(t1 - tSessionBegin > (MAXIMUM_SESSION_LIFE_ms << 10))
		{
			ReplaceTimer(TRASIENT_STATE_TIMEOUT_ms);
			TIMED_OUT();
		}
		//
		if (lowState != COMMITTED)
			KeepAlive();
		break;
	case PRE_CLOSED:
		if((t1 - clockCheckPoint.tMigrate) > (TRASIENT_STATE_TIMEOUT_ms << 10)
		 || t1 - tSessionBegin >  (MAXIMUM_SESSION_LIFE_ms << 10) )
		{
#ifdef TRACE
			printf_s("\nTransient state time out in the %s state\n", stateNames[lowState]);
#endif
			// UNRESOLVED!? But PRE_CLOSED connection might be resurrected
			TIMED_OUT();
		}
		//
		SendPacket<RELEASE>();
		break;
	case CLOSABLE:	// CLOSABLE does not automatically timeout to CLOSED
	case CLOSED:
		if(t1 - tSessionBegin >  (MAXIMUM_SESSION_LIFE_ms << 10))
		{
			ReplaceTimer(TRASIENT_STATE_TIMEOUT_ms);
			if(lowState == CLOSABLE)
				Notify(FSP_Dispose);
			lowState = NON_EXISTENT;
			SetReady();
			return;	// let calling of Extingush() in the NON_EXISTENT state to do cleanup 
		}
		break;
	case CLONING:
		if (t1 - clockCheckPoint.tMigrate > (TRASIENT_STATE_TIMEOUT_ms << 10)
		 || t1 - tSessionBegin >  (MAXIMUM_SESSION_LIFE_ms << 10) )
		{
#ifdef TRACE
			printf_s("\nTransient state time out or key out of life in the %s state\n", stateNames[lowState]);
#endif
			TIMED_OUT();
		}
		EmitStart();
		break;
	case RESUMING:
	case QUASI_ACTIVE:
		if (t1 - tSessionBegin >  (MAXIMUM_SESSION_LIFE_ms << 10) )
		{
#ifdef TRACE
			printf_s("\nTransient state time out or key out of life in the %s state\n", stateNames[lowState]);
#endif
			TIMED_OUT();
		}
		else if(t1 - clockCheckPoint.tMigrate > (TRASIENT_STATE_TIMEOUT_ms << 10))
		{
			ReplaceTimer(SCAVENGE_THRESHOLD_ms);
			Notify(FSP_NotifyTimeout);
			lowState = CLOSED;
			SetReady();
			return;
		}
		EmitStart();
		break;
	}

	if (_InterlockedExchange8(& toUpdateTimer, 0))
		RestartKeepAlive();

	// but if we could possibly query it from the internal information of the timer!
	clockCheckPoint.tKeepAlive = t1 + tKeepAlive_ms * 1000ULL;

	SetReady();
}


// Send heartbeart signal to the remote end, may trigger retransmission of the remote end
/**
-	Retransmission of PERSIST
	An FSP node in the ESTABLISHED state MUST retransmit the unacknowledged PERSIST packet
	at the tempo of transmitting heartbeat signals.
-	Retransmission of COMMIT
	An FSP node in the COMMITTING or COMMITTING2 state MUST retransmit the unacknowledged COMMIT packet
	at the tempo of transmitting heartbeat signals. 
-	LLS should change PERSIST packet to COMMIT if it has migrated to the COMMITTING or COMMITTING2 state
*/
void CSocketItemEx::KeepAlive()
{
	if (pControlBlock->CountUnacknowledged() > 0)
	{
		// it is waste of time if the packet is already acknowledged however it do little harm
		// and it doesn't worth the trouble to handle low-possibility situation
		// prefer productivity over code elegancy
		ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetFirstBufferedSend();
		//
		uint8_t	headOpCode = skb->opCode;
		if (headOpCode == PERSIST)
		{
#ifdef TRACE_PACKET
			printf_s("Keep-alive local fiber#%u, head packet in the queue is happened to be %s\n"
				, fidPair.source
				, opCodeStrings[headOpCode]);
			pControlBlock->DumpSendRecvWindowInfo();
#endif
			// PERSIST/COMMIT packet in the head of the receive queue is the accumulative acknowledgment as well 
			EmitWithICC(skb, pControlBlock->GetSendWindowFirstSN());
			return;
		}
		//
		if (headOpCode == COMMIT)	// assert(skb->len > 0); // not necessarily
			EmitWithICC(skb, pControlBlock->GetSendWindowFirstSN());
	}

	// Send COMMIT or KEEP_ALIVE in heartbeat interval
	BYTE buf[sizeof(FSP_NormalPacketHeader) + MAX_BLOCK_SIZE];
	ControlBlock::seq_t seqExpected;
	int spFull = GenerateSNACK(buf, seqExpected);
#ifdef TRACE_PACKET
	printf_s("Keep-alive local fiber#%u\n"
		"\tAcknowledged seq#%u, keep-alive header size = %d\n"
		, fidPair.source
		, seqExpected
		, spFull);
#endif

	if(spFull < 0)
	{
		printf_s("Fatal error %d encountered when generate SNACK\n", spFull);
		return;
	}
	if(spFull - sizeof(FSP_NormalPacketHeader) < 0)
	{
		TRACE_HERE("HandleMemoryCorruption");
		HandleMemoryCorruption();
		return;
	}

	register FSP_NormalPacketHeader *pHdr = (FSP_NormalPacketHeader *)buf;
	pHdr->hs.Set<KEEP_ALIVE>(spFull);
	pControlBlock->SetSequenceFlags(pHdr, seqExpected);
	SetIntegrityCheckCode(*pHdr);
#ifdef TRACE_PACKET
	printf_s("To send KEEP_ALIVE seq#%u, acknowledge#%u\n", ntohl(pHdr->sequenceNo), seqExpected);
#endif
	SendPacket(1, ScatteredSendBuffers(pHdr, spFull));
}


// Given
//	ControlBlock::seq_t		the maximum sequence number expected by the remote end, without gaps
//	const GapDescriptor *	array of the gap descriptors
//	int						number of gap descriptors
// Do
//	Make acknowledgement, maybe accumulatively if number of gap descriptors is 0
//	And do retransmission if necessary
// Return
//  -EBADF	if gap description insane
//	-EDOM	if parameter error
//	-EFAULT if memory corrupted
//	0 if no error
// Remark
//	An FSP makes retransmission passively in the sense that it only retransmits those explicitly negatively acknowledged
//	FSP is conservative in retransmission in the sense that it treats the KEEP-ALIVE signal as if
//	it were a timer and the interrupt rate should be considerably lower than predefined timer
//	FSP node simply retransmits lost packets of stream payload while ignores milky payload,
//	though we know newer packet are of high priority in retransmission for milky payload
//	while older packets are of higher value for stream payload
//  if n == 0 it is an accumulative acknowledgment
int LOCALAPI CSocketItemEx::RespondSNACK(ControlBlock::seq_t expectedSN, const FSP_SelectiveNACK::GapDescriptor *gaps, int n)
{
	// Check validity of the control block descriptors to prevent memory corruption propagation
	register int32_t	capacity;
	register int32_t	iHead;
	register int32_t	tail;
	ControlBlock::seq_t seqHead = pControlBlock->GetSendWindowFirstSN(capacity, iHead);
	int sentWidth = pControlBlock->CountUnacknowledged();
	int ackSendWidth = int(expectedSN - seqHead);
	if(ackSendWidth == 0 && n != 0)
	{
		TRACE_HERE("ackSendWidth == 0 && n != 0");
		return -EDOM;
	}
	if(ackSendWidth < 0 || ackSendWidth > sentWidth)
	{
		TRACE_HERE("ackSendWidth < 0 || ackSendWidth > sentWidth");
		return -EBADF;
	}
	// if the send window width < 0, it will return -EFAULT: fatal error, maybe memory corruption caused by ULA

	tail = iHead;
	if(tail < 0 || tail >= capacity || sentWidth > capacity)	// here tail is still the head
		return -EFAULT;
	if(sizeof(ControlBlock) + sizeof(ControlBlock::FSP_SocketBuf) * capacity > dwMemorySize)
		return -EFAULT;

	//
	ControlBlock::PFSP_SocketBuf p0 = pControlBlock->HeadSend();
	timestamp_t	tNow = NowUTC();
	uint64_t	rtt64_us = tNow - tEarliestSend;
	bool		acknowledged = false;	// whether the head packet of the send queue is acknowledged 
	uint32_t	countAck = 0;

	retransTail = retransHead = 0;

	if(ackSendWidth == 0)
		goto l_success;

	tail += ackSendWidth - 1;
	if(tail >= capacity)
		tail -= capacity;

	ControlBlock::PFSP_SocketBuf p = p0 + tail;
	ControlBlock::seq_t	seqTail = expectedSN;
	int			k = 0;
	int			nAck;
	bool		lessRecent = false;
	do
	{
		// when n == 0 gaps[k] would not be tested, and it is treated as accumulative acknowledgment
		if(k < n && (gaps[k].dataLength < 0 || gaps[k].gapWidth < 0 || gaps[k].dataLength == 0 && gaps[k].gapWidth == 0))
			return -EBADF;

		nAck = int(seqTail - seqHead);
		if(k < n && nAck > gaps[k].dataLength)
			nAck = gaps[k].dataLength;
		//
		// Make acknowledgement
		while(--nAck >= 0)
		{
			--seqTail;
			// don't care len
			if(! p->GetFlag<IS_ACKNOWLEDGED>())
			{
				p->SetFlag<IS_ACKNOWLEDGED>();
				countAck++;
				if(seqTail == seqHead)
					acknowledged = true;
			}
			//
			if(--tail < 0)
			{
				tail += capacity;
				p = p0 + tail;
			}
			else
			{
				p--;
			}
		}
		// the first (and possibly last) group of continuous acknowledged packets when k == n
		if(k >= n)
			break;
	
		// the gap might cross over the first packet in the send window, as out-of-order NACK might be received
		nAck = min(gaps[k].gapWidth, int32_t(seqTail - seqHead));
		while(nAck-- > 0)
		{
			seqTail--;
			//
			if(! lessRecent)
				lessRecent
				= rtt64_us - (tRecentSend - tEarliestSend) * (seqTail - seqHead) / sentWidth >= tRoundTrip_us * 2;
			if(! p->GetFlag<IS_ACKNOWLEDGED>() && lessRecent)
				retransBackLog[--retransHead] = seqTail;
			//
			if(--tail < 0)
			{
				tail += capacity;
				p = p0 + tail;
			}
			else
			{
				p--;
			}
		}
		//
		k++;
	} while(int(seqTail - seqHead) > 0);

l_success:
	if(congestCtrl.dMin <= 0 || congestCtrl.dMin > rtt64_us)
		congestCtrl.dMin = rtt64_us;
	//
	// Cubic congestion control; additive increase
	//
	while(countAck > 0)	// it is an if. just to avoid goto
	{
		const int SCALE = (1 << 24);
		int ii;
		if(congestCtrl.cwnd < congestCtrl.ssthresh)
		{
			ii = min(countAck, congestCtrl.ssthresh - congestCtrl.cwnd);
			congestCtrl.cwnd += ii;
			if( (countAck -= ii) <= 0)
				break;
		}

		float f = congestCtrl.Update(tNow) * countAck;
		ii = uint32_t(floor(f));
		congestCtrl.cwnd += ii;
		congestCtrl.cwndFraction += uint32_t((f - ii) * SCALE);
		if(congestCtrl.cwndFraction > SCALE)
		{
			congestCtrl.cwnd ++;
			congestCtrl.cwndFraction -= SCALE;
		}
		break;	// 'while' is an if
	}

	// negatively acknowledged in the send queue tail:
	nAck = pControlBlock->CountUnacknowledged(expectedSN);

	// Clearly we're quite relunctant to assume that loss of packet were caused by congestion
	if(nAck > 1 && (tNow - tRecentSend) > tRoundTrip_us)
		congestCtrl.OnCongested();
	else
		congestCtrl.CheckTimeout(tNow);

	// for testability and differentiated transmission policy we do not make real retransmissin yet
	// register retransmission of those sent but not acknowledged after expectedSN
	if(nAck > 0 && retransTail - retransHead < MAX_RETRANSMISSION)
	{
		tail = iHead + ackSendWidth;	// recalibrate it
		if(tail >= capacity)
			tail -= capacity;
		p = p0 + tail;
		seqTail = expectedSN;	// seqHead + ackSendWidth;
		do
		{
			if(rtt64_us - (tRecentSend - tEarliestSend) * (seqTail - seqHead) / sentWidth < tRoundTrip_us * 2)
				break;
			//
			if(! p->GetFlag<IS_ACKNOWLEDGED>())
			{
				if(retransTail - retransHead >= MAX_RETRANSMISSION)
					break;	// for stream payload no further retransmission is possible
				else
					retransBackLog[retransTail++] = seqTail;
			}
			//
			++seqTail;
			if(++tail >= capacity)
			{
				tail -= capacity;
				p = p0 + tail;
			}
			else
			{
				p++;
			}
		} while(--nAck > 0);
	}
	else while(retransTail - retransHead > MAX_RETRANSMISSION)
	{
		retransHead = retransTail - MAX_RETRANSMISSION;
	}

	//	ONLY when the first packet in the send window is acknowledged may round-trip time re-calibrated
	if(acknowledged)
	{
		// UNRESOLVED! to be studied: does RTT increment linearly?
		_InterlockedExchange8(& toUpdateTimer, 1);
		// We assume that after sliding send window the number of unacknowledged was reduced
		pControlBlock->SlideSendWindow();
		RecalibrateKeepAlive(rtt64_us);
#ifdef TRACE
		printf_s("We guess new tEarliestSend based on relatively tRecentSend = %lld\n"
			"\ttEarliestSend = %lld, sendWidth = %d, packets on flight = %d\n"
			, (tNow - tRecentSend)
			, (tNow - tEarliestSend)
			, sentWidth
			, pControlBlock->CountUnacknowledged()
			);
		if(int64_t(tRecentSend - tEarliestSend) < 0 || sentWidth <= pControlBlock->CountUnacknowledged())
			TRACE_HERE("function domain error in guess tEarliestSend");
#endif
		// assert(int64_t(tRecentSend - tEarliestSend) >= 0 && sentWidth > pControlBlock->CountUnacknowledged());
		tEarliestSend += (tRecentSend - tEarliestSend) * (sentWidth - pControlBlock->CountUnacknowledged()) / sentWidth;
#ifdef TRACE
		printf_s("\ttRecentSend - tEarliestSend = %lluus, about %llums\n"
			, (tRecentSend - tEarliestSend)
			, (tRecentSend - tEarliestSend) >> 10
			);
#endif
	}

	return 0;
}



// TODO: testability: output the SNACK structure
// TODO: UNRESOLVED! Just silently discard the malformed packet?
int LOCALAPI CSocketItemEx::RespondSNACK(ControlBlock::seq_t ackSeqNo, const PFSP_HeaderSignature optHdr)
{
	if (optHdr == NULL || optHdr->opCode != SELECTIVE_NACK)
	{
#ifdef TRACE_PACKET
		TRACE_HERE("accumulative acknowledgement");
#endif
		return RespondSNACK(ackSeqNo, NULL, 0);
	}

	FSP_SelectiveNACK::GapDescriptor *gaps
		= (FSP_SelectiveNACK::GapDescriptor *)((BYTE *)headPacket->GetHeaderFSP() + ntohs(optHdr->hsp));
	FSP_SelectiveNACK *pHdr = (FSP_SelectiveNACK *)((BYTE *)optHdr + sizeof(*optHdr) - sizeof(*pHdr));
	int n = int((BYTE *)gaps - (BYTE *)pHdr);
	if (n < 0)
		return -EBADF;	// this is a malformed packet.

	n /= sizeof(FSP_SelectiveNACK::GapDescriptor);
	if (pHdr->lastGap != 0)
		n++;
	for (register int i = n - 1; i >= 0; i--)
	{
		gaps[i].gapWidth = ntohs(gaps[i].gapWidth);
		gaps[i].dataLength = ntohs(gaps[i].dataLength);
	}

	return RespondSNACK(ackSeqNo, gaps, n);
}




// this member function is called by KeepAlive() only. however, for testability we separate this block of code
void CSocketItemEx::RecalibrateKeepAlive(uint64_t rtt64_us)
{
#ifdef TRACE
	TRACE_HERE("to recalibrate keep-alive period");
	printf_s("\tRTT_old is about %ums, tKeepAlive = %ums. Most recent RTT is about %llums\n"
		, tRoundTrip_us >> 10
		, tKeepAlive_ms
		, rtt64_us >> 10);
#endif

	// Note that the raw round trip time includes the heartbeat-delay. See also EarlierKeepAlive()
	uint64_t rttRaw = (rtt64_us + 3) >> 2;
	rttRaw += tRoundTrip_us >> 1;
	tKeepAlive_ms >>= 1;
	tKeepAlive_ms += UINT32(rttRaw >> 9);	// Aproximate 1000/2 with 512
	tRoundTrip_us = UINT32(min(rttRaw, UINT32_MAX));
	// make sure tKeepAlive is not insanely small after calibration
	tKeepAlive_ms = max(tKeepAlive_ms, UINT32(min((rtt64_us + KEEP_ALIVE_TIMEOUT_MIN_us) >> 10, UINT32_MAX)));

#ifdef TRACE
	printf_s("\tCalibrated round trip time = %uus, keep-alive timeout = %ums\n\n", tRoundTrip_us,  tKeepAlive_ms);
#endif
}

void CSocketItemEx::CubicRate::CheckTimeout(timestamp_t t1)
{
	if(T0 > 0 && t1 - T0 > (TRASIENT_STATE_TIMEOUT_ms << 10))
		Reset();
}



void CSocketItemEx::CubicRate::OnCongested()
{
	T0 = 0;
	Wmax = cwnd < Wmax	// fast convergence is always applied
		? cwnd * (2 - CONGEST_CONTROL_BETA) / 2
		: cwnd;
	cwnd = max(cwndMin, uint32_t(cwnd * (1 - CONGEST_CONTROL_BETA)));
	ssthresh = cwnd;
	cwndFraction = 0;
}



void CSocketItemEx::CubicRate::Reset()
{
	Wmax = 0;
	T0 = 0;	// the epoch of last congestion
	originPoint = 0;
	K = 0;
	dMin = 0;
	cwnd = cwndMin = INITIAL_CONGESTION_WINDOW;	// UNRESOLVED! minimum rate guarantee...
	ssthresh = cwnd;
	cwndFraction = 0;
}


// brute-force float-point calculation of increase delta
float CSocketItemEx::CubicRate::Update(timestamp_t t1)
{
	if (T0 <= 0)
	{
		T0 = t1;
		if (cwnd < Wmax)
		{
			K = CubicRoot((Wmax - cwnd) / CONGEST_CONTROL_C);
			originPoint = uint32_t(Wmax);
		}
		else
		{
			K = 0;
			originPoint = cwnd;
		}
	}
	// The unit of the time
	double W = CONGEST_CONTROL_C * CubicPower((t1 + dMin - T0) * 1e-6) + originPoint;
	// some anti-alias measure should be taken by the caller
	return float(W > cwnd ? W / cwnd - 1 : 0.01); 
}
