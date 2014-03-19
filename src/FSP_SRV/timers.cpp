/*
 * FSP lower-layer service program, software time-wheel, might be accelerated by hardware
 * heartbeat callback and its related functions to
 * - retransmit INITIATE_CONNECT, CONNECT_REQUEST, RESTORE or MULTIPLY
 * - send heartbeat signal PERSIST
 * - idle timeout of CONNECT_BOOTSTRAP, CONNECT_AFFIRMING, QUASI_ACTIVE, CLONING
 *	 or CHALLENGING, as well as ACTIVE, RESUMING or PAUSING state
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
  When a socket is created the alarm clock is not initiated. Instead, the alarm clock is initiated
  when a first time-out event handler is registered in the timewheel:
  1.INIT_CONNECT family, init_connect retransmission, registered when Emit INIT_CONNECT.
	It is the time when the initiator starts the time-out mechanism
  2.connect_request retransmission, inherits the time-out clock of init_connect retransmission
  3.INIT_CONNECT family, multiply retransmissin, registered when Emit MULTIPLY
  4.INIT_CONNECT family, restore retransmission, registered when Emit RESTORE
  5.Transient State Timeout family, challenging timeout, registered when Emit ACK_CONNECT_REQUEST
	It is the time when the responder starts the time-out mechanism
  6.KEEP_ALIVE family, persist heartbeat, the timeout interval updated when Emit PERSIST
  7.KEEP_ALIVE family, adjourn heartbeat, the timeout interval of 'persist heartbeat' inherited
	updated on getting the first ADJOURN packet of the cloned connection
  8.scavenging event, registered when Emit FINISH in the CLOSABLE state (and it is migrated to CLOSED state)
	or when get ACK_ADJOURN packet in the PAUSING state (and it is migrated to CLOSABLE state)

  Timeout is almost always notified to ULA
	[Retransmit INIT_CONNECT timeout]	CONNECT_BOOTSTRAP-->NON_EXISTENT
	[Retransmit CONNECT_REQUEST timeout]CONNECT_AFFIRMING-->NON_EXISTENT
	[Retransmit RESTORE Timeout] {QUASI_ACTIVE, RESUMING}-->CLOSED
	[Retransmit MULTIPLY Timeout] CLONING-->NON_EXISTENT

  ACK_INIT_CONNECT or FINISH is never retransmitted.
  ACK_CONNECT_REQUEST, PURE_DATA or ACK_FLUSH is retransmitted on demand.
  Continual PERSIST or ADJOURN packets are sent as heart-beating signals.

  Garbage Collecting occurs when it timeouts in CHANLLENGING, CLOSABLE, or CLOSED state where resource is to be freed.

  Heartbeat_Interval_0 = RTT0 << 2
  RTT_N = Max(1, Average(persist_time - send_time) - Heartbeat_Interval_N)
  Heartbeat_Interval_(N+1) = Heartbeat_Interval_N  - (Heartbeat_Interval_N >> 2) + RTT_N
  The actual heartbeat interval should be no less than one OS time slice interval 
**/



// Timeout of initiation family retransmission, keep-alive transmission and Scanvenger activation
// State idle timeout
// A SCB in the CLOSABLE state could be restored while in the CLOSED state could be resurrected
// Remark
//	Transient-state timeout is only possible in CONNECT_BOOTSTRAP, CONNECT_AFFIRMING, CLONING, CHALLENGING
//	or QUASI_ACTIVE state, where the check point clock 'tMigrate' was set in the subroutine AddTimer()
void CSocketItemEx::TimeOut()
{
	if(! this->TestAndLockReady())
		return;
	//
	timestamp_t t1 = NowUTC();
	switch(lowState)
	{
	case NON_EXISTENT:
		Extinguish();
		break;
	// Note that CONNECT_BOOTSTRAP and CONNECT_AFFIRMING are counted into one transient period
	case CONNECT_BOOTSTRAP:
	case CONNECT_AFFIRMING:
	case CLONING:
	case CHALLENGING:
		if(t1 - clockCheckPoint.tMigrate > (TRASIENT_STATE_TIMEOUT_ms << 10))
		{
#ifdef TRACE
			printf_s("\nTransient state time out in state %s\n", stateNames[lowState]);
#endif
			if(! Notify(FSP_NotifyDisposed))
				break;
			// Wait some time to let DLL do cleaning work at first
			lowState = NON_EXISTENT;
			break;
		}
		// TO BE TESTED...
		if(lowState != CHALLENGING)
			Retransmit1();
		break;
	case ESTABLISHED:
	case PAUSING:
	case RESUMING:
		if(t1 - tSessionBegin > (MAXIMUM_SESSION_LIFE_ms << 10) || t1 - tLastRecv > (SCAVENGE_THRESHOLD_ms << 10))
		{
			if(! Notify(FSP_NotifyDisposed))
				break;
			ReplaceTimer(TRASIENT_STATE_TIMEOUT_ms);
			// Wait some time to let DLL do cleaning work at first
			lowState = NON_EXISTENT;
			break;
		}
		// TO BE TESTED...
		if(lowState == ESTABLISHED)
			KeepAlive();
		else if(lowState == PAUSING)
			Flush();
		else
			Retransmit1();
		break;
	// UNRESOLVED! make difference of SCAVENGE_THRESHOLD and TIME_WAIT_TO_CLOSE?
	case CLOSABLE:
	case CLOSED:
		if(t1 - tSessionBegin >  (MAXIMUM_SESSION_LIFE_ms << 10))
			Extinguish();
		else
			SetState(CLOSED);
		break;
	case QUASI_ACTIVE:
		if( t1 - clockCheckPoint.tMigrate > (TRASIENT_STATE_TIMEOUT_ms << 10)
		 || t1 - tSessionBegin >  (MAXIMUM_SESSION_LIFE_ms << 10) )
		{
#ifdef TRACE
			printf_s("\nTransient state time out or key out of life in the QUASI_ACTIVE state\n");
#endif
			if(! Notify(FSP_Timeout))
				break;
			//
			ReplaceTimer(SCAVENGE_THRESHOLD_ms);
			lowState = CLOSED;
			break;
		}
		// TO BE TESTED...
		Retransmit1();
		break;
	}

	SetReady();
}



// Send heartbeart signal to the remote end, may trigger retransmission of the remote end
// If the first packet in the send queue is PERSIST or ADJOURN (and it is unacknowledged)
// the packet is resent, or else either an out-of-band KEEP_ALIVE whose sequence number is
// of the next to send is sent 
void CSocketItemEx::KeepAlive()
{
	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend()+ pControlBlock->sendWindowHeadPos;
	if((skb->opCode == PERSIST || skb->opCode == ADJOURN)
	 && pControlBlock->sendBufferNextSN != pControlBlock->sendWindowFirstSN)
	{
#ifdef TRACE
		printf_s("Keep-alive session#%u, head packet in the queue is happened to be %s\n"
			, pairSessionID.source
			, opCodeStrings[skb->opCode]);
#endif
		// UNRESOLVED! Could sendWindowHeadPos and sendWindowFirstSN update in an atomic manner?
		// it is waste of time if the packet is already acknowledged however it do little harm
		// and it doesn't worth the trouble to handle low-possibility situation
		Retransmit1();
		return;
	}

	BYTE buf[sizeof(FSP_NormalPacketHeader) + MAX_BLOCK_SIZE];
	ControlBlock::seq_t seqExpected;
	int spFull = GenerateSNACK(buf, seqExpected);
#ifdef TRACE
	printf_s("Keep-alive session#%u\n"
		"\tSend head - tail = %d - %d, recv head - tail = %d - %d\n"
		"\tAcknowledged seq#%u, keep-alive header size = %d\n"
		, pairSessionID.source
		, pControlBlock->sendWindowHeadPos
		, pControlBlock->sendBufferNextPos
		, pControlBlock->recvWindowHeadPos
		, pControlBlock->recvWindowNextPos
		, seqExpected
		, spFull);
#endif

	if(spFull < 0)
	{
#ifdef TRACE
		printf_s("Fatal error %d encountered when generate SNACK\n", spFull);
#endif
		return;
	}
	if(spFull - sizeof(FSP_NormalPacketHeader) < 0)
	{
#ifdef TRACE
		TRACE_HERE("HandleMemoryCorruption");
#endif
		HandleMemoryCorruption();
		return;
	}

	// Always try to piggyback the KEEP_ALIVE signal on a normal, pure data packet at first
	ControlBlock::seq_t seq0 = pControlBlock->sendWindowNextSN;
	if( spFull - sizeof(FSP_NormalPacketHeader) == 0
	&& (skb = pControlBlock->PeekNextToSend()) != NULL
	&& (skb->opCode == PURE_DATA && skb->GetFlag<IS_COMPLETED>() && skb->MarkInSending()
		|| skb->opCode == KEEP_ALIVE)
	)
	{
#ifdef TRACE
		printf_s("\tTo send back an accumulative acknowledgement.\n");
#endif
		// UNRESOLVED! If it is yet out of send window, send an out-of-band packet with null payload instead
		skb->opCode = KEEP_ALIVE;
		if(! Emit(skb, seq0))
		{
			skb->opCode = PURE_DATA;
			skb->MarkUnsent();
		}
		return;
	}

	register FSP_NormalPacketHeader *pHdr = (FSP_NormalPacketHeader *)buf;
	--seq0;	// this is an absolutely out-of-band command packet
	pHdr->hs.Set<KEEP_ALIVE>(spFull);
	pHdr->sequenceNo = htonl(seq0);
	pHdr->expectedSN = htonl(seqExpected);
	pHdr->ClearFlags();	// pHdr->u.flags = 0;
	// here we needn't check memory corruption as mishavior only harms himself
	pHdr->SetRecvWS(pControlBlock->RecvWindowSize());
	SetIntegrityCheckCode(*pHdr);
#ifdef TRACE
	printf_s("To send KEEP_ALIVE seq#%u, acknowledge#%u\n", seq0, seqExpected);
#endif
	SendPacket(1, ScatteredSendBuffers(pHdr, spFull));
}



// LLS sends packet in the send queue orderly to the remote end, including the ADJOURN packet
// See also SlideSendWindow()
void CSocketItemEx::Flush()
{
#ifdef TRACE
	printf("Flushing session#%u\n"
		"\tSend head - tail = %d - %d, recv head - tail = %d - %d\n"
		, pairSessionID.source
		, pControlBlock->sendWindowHeadPos
		, pControlBlock->sendBufferNextPos
		, pControlBlock->recvWindowHeadPos
		, pControlBlock->recvWindowNextPos);
#endif
	pControlBlock->SlideSendWindow();	// if it is not done already
	//
	if (pControlBlock->CountSendBuffered() <= 0)
	{
		ReplaceTimer(SCAVENGE_THRESHOLD_ms);
		SetState(CLOSABLE);
		return;
	}

	Retransmit1();
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
//	FSP do retransmission passively, only retransmit those explicitly negatively acknowledged
//	treat the KEEP-ALIVE signal as if it were a timer interrupt
//	for testability and differentiated transmission policy we do not make real retransmissin yet
//	ONLY when the first packet in the send window is acknowledged may round-trip time re-calibrated
int LOCALAPI CSocketItemEx::RespondSNACK(ControlBlock::seq_t expectedSN, const FSP_SelectiveNACK::GapDescriptor *gaps, int n)
{
	if(isMilky || n < 0)
	{
		TRACE_HERE("isMilky || n < 0");
		return -EDOM;
	}

	// Check validity of the control block descriptors to prevent memory corruption propagation
	const int seqHead = pControlBlock->sendWindowFirstSN;
	int sentWidth = int(pControlBlock->sendWindowNextSN - seqHead);
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

	const int	capacity = pControlBlock->sendBufferBlockN;
	int			tail = pControlBlock->sendWindowHeadPos;
	if(tail < 0 || tail >= capacity || sentWidth > capacity)	// here tail is still the head
		return -EFAULT;
	if(sizeof(ControlBlock) + sizeof(ControlBlock::FSP_SocketBuf) * capacity > dwMemorySize)
		return -EFAULT;

	//
	ControlBlock::PFSP_SocketBuf p0 = pControlBlock->HeadSend(); 
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
	bool		acknowledged = false;
	do
	{
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
				if(seqTail == pControlBlock->sendWindowFirstSN)
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
		// for milky payload, newer packet are of high priority when retransmitting
		// while for stream payload older packets are of higher value
		while(nAck-- > 0)
		{
			seqTail--;
			// Simply retransmit stream payload and ignore milky payload
			if(! p->GetFlag<IS_ACKNOWLEDGED>())
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

	if(acknowledged)
	{
		uint32_t	rtt_us = uint32_t(NowUTC() - tEarliestSend);
		tRoundTrip_us = (tRoundTrip_us >> 2) + (tRoundTrip_us >> 1) + ((rtt_us + 3) >> 2);
		tRoundTrip_us -= tKeepAlive_ms * 250;
		// it is assumed that RTT is about the same in the upstream and the downstream direction
		// tKeepAlive = 4RTT and delay of lazy acknowledgement is RTT. fight against the cheater
		tKeepAlive_ms = tKeepAlive_ms - (tKeepAlive_ms >> 2) + tRoundTrip_us / 1000;
		if(tKeepAlive_ms < KEEP_ALIVE_TIMEOUT_MIN_ms)
			tKeepAlive_ms = KEEP_ALIVE_TIMEOUT_MIN_ms;
		//
		ChangeKeepAliveClock();
		pControlBlock->SlideSendWindow();
		tEarliestSend += (tRecentSend - tEarliestSend)
			* (sentWidth - int(pControlBlock->sendWindowNextSN - seqHead))
			/ sentWidth;
#ifdef TRACE
		printf_s("\nCalibrated round trip time: %dus, keep-alive timeout: %dms\n\n", tRoundTrip_us,  tKeepAlive_ms);
#endif
	}	

l_success:
	// register retransmission of those sent but not acknowledged after expectedSN
	if(retransTail - retransHead < MAX_RETRANSMISSION && (nAck = int(pControlBlock->sendWindowNextSN - expectedSN)) > 0)
	{
		tail = pControlBlock->sendWindowHeadPos + ackSendWidth;
		if(tail >= capacity)
			tail -= capacity;
		p = p0 + tail;
		seqTail = expectedSN;	// seqHead + ackSendWidth;
		do
		{
			// UNRESOLVED! TODO: estimate send time of the packet
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
	else if(retransTail - retransHead > MAX_RETRANSMISSION)
	{
		retransHead =  retransTail - MAX_RETRANSMISSION;
	}

	return 0;
}
