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
		// If the peer has committed an ACK_FLUSH has accumulatively acknowledged it.
		// The near end needn't send periodical KEEP_ALIVE anymore
		// UNRESOLVED! TODO: but a lower frequence KEEP_ALIVE is a MUST?
		if (lowState != PEER_COMMIT)
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
				SendPacket<RESET>();	// See also Disconnect
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
			Notify(FSP_NotifyTimeout);
			SetReady();
			CloseSocket();
			return;
		}
		EmitStart();
		break;
	}

	if (_InterlockedExchange8(& toUpdateTimer, 0))
		RestartKeepAlive();

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
#if defined(TRACE_HEARTBEAT) || defined(TRACE_PACKET)
	printf_s("Keep-alive local fiber#%u\n", fidPair.source);
	DumpTimerInfo(NowUTC());
#endif
	// It is waste of time if the packet is already acknowledged. However it does little harm
	// and it doesn't worth the trouble to handle low-possibility situation
	// Prefer productivity over code elegancy
	if (pControlBlock->CountSentInFlight() > 0)
	{
		ControlBlock::PFSP_SocketBuf skb = pControlBlock->GetSendQueueHead();
		//
		uint8_t	headOpCode = skb->opCode;
		if (headOpCode == PERSIST || headOpCode == COMMIT)
		{
#if defined(TRACE_HEARTBEAT) || defined(TRACE_PACKET)
			printf_s("Keep-alive local fiber#%u, head packet in the queue is happened to be %s\n"
				, fidPair.source
				, opCodeStrings[headOpCode]);
			pControlBlock->DumpSendRecvWindowInfo();
#endif
			EmitWithICC(skb, pControlBlock->sendWindowFirstSN);
		}
	}

	// Only in ESTABLISHED, COMMITTING, COMMITTING2 or COMMITTED state may KEEP_ALIVE be sent
	SendSNACK(KEEP_ALIVE);
}



// Take the network-order acknowledgement timestamp as the salt to SetIntegrityCheckCode for KEEP_ALIVE/ACK_FLUSH
// Send KEEP_ALIVE or it special norm, ACK_FLUSH
bool CSocketItemEx::SendSNACK(FSPOperationCode opCode)
{
	ControlBlock::seq_t seqExpected;
	FSP_PreparedKEEP_ALIVE buf;

	int32_t len = GenerateSNACK(buf, seqExpected);
#if defined(TRACE_PACKET) || defined(TRACE_HEARTBEAT)
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

	// Both KEEP_ALIVE and ACK_FLUSH are payloadless out-of-band control block which always apply current session key
	// See also ControlBlock::SetSequenceFlags
	buf.hdr.sequenceNo = htobe32(pControlBlock->sendWindowNextSN - 1);
	buf.hdr.expectedSN = htobe32(seqExpected);
	buf.hdr.ClearFlags();
	buf.hdr.SetRecvWS(pControlBlock->RecvWindowSize());

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
int LOCALAPI CSocketItemEx::RespondToSNACK(ControlBlock::seq_t expectedSN, FSP_SelectiveNACK::GapDescriptor *gaps, int n)
{
	const int32_t capacity = pControlBlock->sendBufferBlockN;
	if(sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * capacity > dwMemorySize)
		return -EFAULT;

	const int sentWidth = pControlBlock->CountSentInFlight();
	if(sentWidth < 0)
		return -EFAULT;
	if(sentWidth == 0)
		return 0;	// there is nothing to be acknowledged

	const int nAck = pControlBlock->DealWithSNACK(expectedSN, gaps, n);
#if defined(TRACE_HEARTBEAT) || defined(TRACE_PACKET)
	printf_s("Accumulatively acknowledged SN = %u, %d packet(s) acknowledged.\n", expectedSN, nAck);
#endif
	if(nAck < 0)
		return nAck;
	// Shall not return on nAck == 0: we care about implicitly negatively acknowledged tail packets as well
	// here is the key point that SNACK may make retransmission more efficient than per-packet timed-out(?)

	// pre-calculate whether the first packet on flight is acknowledged
	bool acknowledged = pControlBlock->GetSendQueueHead()->GetFlag<IS_ACKNOWLEDGED>();
	// pre-calculate, for they're volatile
	uint64_t	tdiff64_us = uint64_t(tRecentSend - tEarliestSend);
	uint64_t	rtt64_us = NowUTC() - tEarliestSend;
	if(gaps == NULL)
		goto l_retransmitted;

	int64_t		rtt_delta = int64_t(rtt64_us - ((uint64_t)tRoundTrip_us << 1));
	if(rtt_delta <= 0)
		goto l_retransmitted;

	register uint32_t	largestOffset;
	if(int64_t(rtt_delta - tdiff64_us) >= 0)
	{
		largestOffset = sentWidth;
		// if the unsigned tdiff64_us == 0, it falled into this category
	}
	else
	{
		// partially unrolled loop
		uint64_t hiqword = (rtt_delta >> 32) * sentWidth;	// The initial remainder, actually;
		uint32_t lodword = ((rtt_delta & 0xFFFFFFFF) * sentWidth) & 0xFFFFFFFF;
		hiqword += ((rtt_delta & 0xFFFFFFFF) * sentWidth) >> 32;
		// We are sure 31st bit of sendWidth is 0 thus 63rd bit of hiqword is 0
		largestOffset = 0;
		for(register int i = 31; i >= 0; i--)
		{
			hiqword <<= 1;
			hiqword |= BitTest((LONG *) & lodword, i);
			if(hiqword >= tdiff64_us)
			{
				hiqword -= tdiff64_us;
				BitTestAndSet((LONG *) & largestOffset, i);
			}
		}
		//
		if(largestOffset == 0)
			goto l_retransmitted;
	}

	const ControlBlock::seq_t headSN = pControlBlock->sendWindowFirstSN;
	register ControlBlock::seq_t seq0 = expectedSN;
	register int32_t index1 = pControlBlock->sendWindowHeadPos + (seq0 - headSN);
	register ControlBlock::PFSP_SocketBuf p;
	for(int k = 0; k < n; k++)
	{
		if(int32_t(index1 - capacity) >= 0)
			index1 = int32_t(index1 - capacity);
		p = pControlBlock->HeadSend() + index1;
		//
		for(uint32_t j = 0; j < gaps[k].gapWidth; j++)
		{
			if(! p->GetFlag<IS_COMPLETED>())	// due to parallism the last 'gap' may include imcomplete buffered data
			{
#if defined(TRACE_PACKET) || defined(TRACE_HEARTBEAT)
				printf_s("Imcomplete packet: SN = %u, index position = %d\n", seq0, index1);
#endif
				goto l_retransmitted;
			}
			if(uint32_t(seq0 - headSN) > largestOffset)
			{
#if defined(TRACE_HEARTBEAT) || defined(TRACE_PACKET)
				printf_s("NACK largest offset = %u\n", largestOffset);
#endif
				goto l_retransmitted;
			}
			// Attention please! If you try to trace the packet it would not be retransmitted, for sake of testability
#if defined(TRACE_PACKET) || defined(TRACE_HEARTBEAT)
			printf_s("Meant to retransmit: SN = %u, index position = %d\n", seq0, p - pControlBlock->HeadSend());
#endif
#ifndef TRACE_PACKET
			if(! p->GetFlag<IS_ACKNOWLEDGED>() && ! EmitWithICC(p, seq0))
				goto l_retransmitted;
#endif
			//
			++seq0;
			if(++index1 - capacity >= 0)
			{
				index1 = 0;
				p = pControlBlock->HeadSend();
			}
			else
			{
				p++;
			}
		}
		//
		seq0 += gaps[k].dataLength;
		index1 += gaps[k].dataLength;
	}
	// seq0 is out of life when the loop terminated, so that the last 'dataLength', which may be overlaid by the SNACK head signature, is just ignored.

l_retransmitted:
	//	ONLY when the first packet in the send window is acknowledged and retransmission queue has been built may round-trip time re-calibrated
	if(acknowledged)	// assert(sentWidth > 0);
	{
		// UNRESOLVED! to be studied: does RTT increment linearly?
		_InterlockedExchange8(& toUpdateTimer, 1);
		// We assume that after sliding send window the number of unacknowledged was reduced
		pControlBlock->SlideSendWindow();
		RecalibrateKeepAlive(rtt64_us);
#ifdef TRACE
		printf_s("We guess new tEarliestSend based on relatively tRecentSend = %lld\n"
			"\ttEarliestSend = %lld, sendWidth = %d, packets on flight = %d\n"
			, (rtt64_us + tEarliestSend - tRecentSend)	// Equal saved 'NowUTC()' - tRecentSend
			, rtt64_us	// Saved 'NowUTC()' - tEarliestSend
			, sentWidth
			, pControlBlock->CountSentInFlight()
			);
		if(int64_t(tdiff64_us) < 0 || sentWidth <= pControlBlock->CountSentInFlight())
			TRACE_HERE("function domain error in guess tEarliestSend");
		// assert(int64_t(tRecentSend - tEarliestSend) >= 0 && sentWidth > pControlBlock->CountSentInFlight());
#endif
		tEarliestSend += tdiff64_us * (sentWidth - pControlBlock->CountSentInFlight()) / sentWidth;
#ifdef TRACE
		printf_s("\ttRecentSend - tEarliestSend = %lluus, about %llums\n"
			, (tRecentSend - tEarliestSend)
			, (tRecentSend - tEarliestSend) >> 10
			);
#endif
	}

	return nAck;
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



void CSocketItemEx::CalibrateKeepAlive()
{
	tLastRecv = NowUTC();
	// The timer was already started for transient state management when SynConnect() or sending MULTIPLY/RESUME
	tRoundTrip_us = (uint32_t)min(UINT32_MAX, tLastRecv - tRecentSend);
	tKeepAlive_ms = tRoundTrip_us >> 8;
#ifndef NDEBUG
	DumpTimerInfo(tLastRecv);
#endif
}