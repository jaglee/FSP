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
		ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetSendQueueHead();
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
			EmitWithICC(skb, pControlBlock->sendWindowFirstSN);
			return;
		}
		//
		if (headOpCode == COMMIT)	// assert(skb->len > 0); // not necessarily
			EmitWithICC(skb, pControlBlock->sendWindowFirstSN);
	}

	SendSNACK(KEEP_ALIVE);
}



// Take the network-order acknowledgement timestamp as the salt to SetIntegrityCheckCode for KEEP_ALIVE/ACK_FLUSH
// Send KEEP_ALIVE or it special norm, ACK_FLUSH
bool CSocketItemEx::SendSNACK(FSPOperationCode opCode)
{
	ControlBlock::seq_t seqExpected;
	FSP_PreparedKEEP_ALIVE buf;

	int32_t len = GenerateSNACK(buf, seqExpected);
#ifdef TRACE_PACKET
	printf_s("Keep-alive local fiber#%u\n"
		"\tAcknowledged seq#%u, keep-alive header size = %d\n"
		, fidPair.source
		, seqExpected
		, len);
#endif
	if(len < sizeof(FSP_SelectiveNACK))
	{
		printf_s("Fatal error %d encountered when generate SNACK\n", len);
		return false;
	}
	len += sizeof(FSP_NormalPacketHeader);

	buf.hdr.hs.version = THIS_FSP_VERSION;
	buf.hdr.hs.opCode = opCode;
	buf.hdr.hs.hsp = htobe16(uint16_t(len));

	pControlBlock->SetSequenceFlags(& buf.hdr, seqExpected);
	SetIntegrityCheckCode(& buf.hdr, NULL, 0, buf.GetSaltValue());
#ifdef TRACE_PACKET
	printf_s("To send KEEP_ALIVE seq #%u, acknowledge #%u, source ALFID = %u\n", be32toh(buf.hdr.sequenceNo), seqExpected, fidPair.source);
	printf_s("KEEP_ALIVE total header length: %d, should be payloadless\n", len);
	DumpNetworkUInt16((uint16_t *) & buf, len / 2);
#endif

	return SendPacket(1, ScatteredSendBuffers(& buf.hdr, len)) > 0;
}


// Given
//	ControlBlock::seq_t		the accumulatedly acknowledged sequence number
//	const GapDescriptor *	array of the gap descriptors
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
//	An FSP makes retransmission passively in the sense that it only retransmits those explicitly negatively acknowledged
//	FSP is conservative in retransmission in the sense that it treats the KEEP-ALIVE signal as if
//	it were a timer and the interrupt rate should be considerably lower than predefined timer
//	and is active optimistic in the sense that retransmission would NOT be withheld by congestion control
//	FSP node simply retransmits lost packets of stream payload while ignores milky payload
//  It is an accumulative acknowledgment if n == 0
int LOCALAPI CSocketItemEx::RespondToSNACK(ControlBlock::seq_t expectedSN, const FSP_SelectiveNACK::GapDescriptor *gaps, int n)
{
	const int32_t & capacity = pControlBlock->sendBufferBlockN;
	int32_t	iHead = pControlBlock->sendWindowHeadPos;
	ControlBlock::seq_t seq0 = pControlBlock->sendWindowFirstSN;
	if(sizeof(ControlBlock) + sizeof(ControlBlock::FSP_SocketBuf) * capacity > dwMemorySize)
		return -EFAULT;

	int sentWidth = pControlBlock->CountUnacknowledged();
	int nAck = pControlBlock->DealWithSNACK(expectedSN, gaps, n);
	if(nAck < 0)
		return nAck;

	ControlBlock::PFSP_SocketBuf p = pControlBlock->HeadSend() + iHead;
	timestamp_t	tNow = NowUTC();
	uint64_t	rtt64_us = tNow - tEarliestSend;
	bool acknowledged = nAck > 0 ? p->GetFlag<IS_ACKNOWLEDGED>() : false;
	// here is the key point that SNACK may make retransmission more efficient than time-outed retransmission
	uint32_t largestOffset = int64_t(tRecentSend - tEarliestSend) > 0
		? uint32_t((rtt64_us - tRoundTrip_us * 2) * sentWidth / (tRecentSend - tEarliestSend))
		: uint32_t(rtt64_us > tRoundTrip_us * 2);	// exploit the fact that boolean true == 1, false == 0

	if(largestOffset <= 0)
		goto l_retransmitted;
	//
	ControlBlock::seq_t headSN = seq0; 
	seq0 = expectedSN;
	for(register int k = 0; k < n - 1; k++)
	{
		if(int(seq0 - headSN + iHead - capacity) >= 0)
			p = pControlBlock->HeadSend() + int(seq0 - headSN + iHead - capacity);
		else
			p = pControlBlock->HeadSend() + int(seq0 - headSN + iHead);
		for(register uint32_t j = 0; j < gaps[k].gapWidth; seq0++, j++)
		{
			if(uint32_t(seq0 - headSN) > largestOffset)
				goto l_retransmitted;
			// Attention please! If you try to trace the packet it would not be retransmitted, for sake of testability
#ifdef TRACE_PACKET
			printf_s("Meant to retransmit: SN = %u\n", seq0);
#else
			if(! EmitWithICC(p, seq0))
				goto l_retransmitted;
#endif
			//
			if(++iHead - capacity >= 0)
			{
				iHead = 0;
				p = pControlBlock->HeadSend();
			}
			else
			{
				p++;
			}
		}
		//
		seq0 += gaps[k].dataLength;
	}

l_retransmitted:
	//	ONLY when the first packet in the send window is acknowledged and retransmission queue has been built may round-trip time re-calibrated
	if(acknowledged)	// assert(sentWidth > 0);
	{
		// UNRESOLVED! to be studied: does RTT increment linearly?
		_InterlockedExchange8(& toUpdateTimer, 1);
		// We assume that after sliding send window the number of unacknowledged was reduced
		pControlBlock->SlideSendWindow();
		RecalibrateKeepAlive(rtt64_us);
#ifdef TRACE_PACKET
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
#ifdef TRACE_PACKET
		printf_s("\ttRecentSend - tEarliestSend = %lluus, about %llums\n"
			, (tRecentSend - tEarliestSend)
			, (tRecentSend - tEarliestSend) >> 10
			);
#endif
	}

	return nAck;
}



// return number of packets acknowledged
int LOCALAPI CSocketItemEx::RespondToSNACK(ControlBlock::seq_t ackSeqNo, const PFSP_HeaderSignature pHdr)
{
	if (pHdr == NULL || pHdr->opCode != SELECTIVE_NACK)
	{
#ifdef TRACE_PACKET
		TRACE_HERE("accumulative acknowledgement");
#endif
		return RespondToSNACK(ackSeqNo, NULL, 0);
	}

	int len = be16toh(pHdr->hsp) - sizeof(FSP_NormalPacketHeader);
	FSP_SelectiveNACK *pRightEdge = (FSP_SelectiveNACK *)((BYTE *)pHdr + sizeof(FSP_HeaderSignature) - sizeof(FSP_SelectiveNACK));

	if(int(pRightEdge->ackTime - tLastAck) <= 0)
		return 0;
	tLastAck = pRightEdge->ackTime;

	FSP_SelectiveNACK::GapDescriptor *gaps = (FSP_SelectiveNACK::GapDescriptor *)((BYTE *)pHdr + sizeof(FSP_HeaderSignature) - len);
	int n = len - sizeof(FSP_SelectiveNACK);
	if (n < 0)
		return -EBADF;	// this is a malformed packet.

	n /= sizeof(FSP_SelectiveNACK::GapDescriptor);
	for(register int i = 0; i < n; i++)
	{
		gaps[i].gapWidth = be32toh(gaps[n].gapWidth);
		gaps[i].dataLength = be32toh(gaps[n].dataLength);
	}

	return RespondToSNACK(ackSeqNo, gaps, n);
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
	tKeepAlive_ms += uint32_t(rttRaw >> 9);	// Aproximate 1000/2 with 512
	tRoundTrip_us = uint32_t(min(rttRaw, UINT32_MAX));
	// make sure tKeepAlive is not insanely small after calibration
	tKeepAlive_ms = max(tKeepAlive_ms, uint32_t(min((rtt64_us + KEEP_ALIVE_TIMEOUT_MIN_us) >> 10, UINT32_MAX)));

#ifdef TRACE
	printf_s("\tCalibrated round trip time = %uus, keep-alive timeout = %ums\n\n", tRoundTrip_us,  tKeepAlive_ms);
#endif
}
