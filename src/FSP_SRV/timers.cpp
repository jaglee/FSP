/*
 * FSP lower-layer service program, software time-wheel, might be accelerated by hardware
 * heartbeat callback and its related functions to
 * - retransmit INITIATE_CONNECT, CONNECT_REQUEST, PERSIST or MULTIPLY
 * - send heartbeat signal KEEP_ALIVE
 * - idle timeout of CONNECT_BOOTSTRAP, CONNECT_AFFIRMING, CLONING or CHALLENGING,
 * - as well as ACTIVE, COMMITTING, COMMITTING2, or PRE_CLOSED state
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
  ACK_CONNECT_REQ, PURE_DATA or ACK_FLUSH is retransmitted on demand.
  ACK_INIT_CONNECT is never retransmitted.

  Timeout is almost always notified to ULA
  
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

  timeouts:
	- transaction commit [LLS: send COMMIT to ACK_FLUSH]
	  {COMMITTING, COMMITTING2}-->NON_EXISTENT
	- transient state
	  CLONING-->NON_EXISTENT
	- retransmit: connect request, update peer's home address
	  {CONNECT_BOOTSTRAP, CHALLENGING, CONNECT_AFFIRMING}-->NON_EXISTENT
	- shutdown
	  {PRE_CLOSED}-->NON_EXISTENT
	- keep-alive
**/

// let calling of Destroy() in the NON_EXISTENT state to do cleanup 
#define TIMED_OUT() \
		Notify(FSP_NotifyTimeout);	\
		lowState = NON_EXISTENT;	\
		SetReady();	\
		return


// A low frequence KEEP_ALIVE is a MUST
void CSocketItemEx::KeepAlive()
{
	if(! this->TestAndLockReady())
	{
		if (!IsInUse())
		{
			TRACE_HERE("Lazy garbage collection, in case of leakage");
			Destroy();
		}
#ifdef TRACE
		printf_s("\n#0x%X's KeepAlive not executed due to lack of locks in state %s. InUse: %d\n"
			, fidPair.source, stateNames[lowState], IsInUse());
#endif
		return;
	}

	timestamp_t t1 = NowUTC();
#if defined(TRACE) && (TRACE & TRACE_HEARTBEAT)
	TRACE_HERE(" it's time-outed");
	//DumpTimerInfo(t1);
#endif
	switch(lowState)
	{
	case NON_EXISTENT:
		TRACE_HERE("After Destroy it needn't SetReady();");
		if(pControlBlock != NULL)
			pControlBlock->state = NON_EXISTENT;
		Destroy();
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
	case COMMITTING:
	case COMMITTED:
	case PEER_COMMIT:
	case COMMITTING2:
		if(t1 - tSessionBegin > (MAXIMUM_SESSION_LIFE_ms << 10))
		{
#ifdef TRACE
			printf_s("\nSession time out in the %s state\n", stateNames[lowState]);
#endif
			ReplaceTimer(TRASIENT_STATE_TIMEOUT_ms);
			TIMED_OUT();
		}
		// If the peer has committed an ACK_FLUSH has accumulatively acknowledged it.
		// The near end needn't send periodical KEEP_ALIVE anymore
		if (lowState != PEER_COMMIT)
			SendKeepAlive();
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
				SendPacket<RESET>();	// See also Reject
			TIMED_OUT();
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
	}

	SetReady();
}



/**
-	Retransmission of PERSIST
	An FSP node MUST retransmit the unacknowledged PERSIST packet at the head of the send queue
	at the tempo of transmitting heartbeat signals.
-	Retransmission of COMMIT
	An FSP node MUST retransmit the unacknowledged COMMIT packet at the head of the send queue
	at the tempo of transmitting heartbeat signals. 
*/
void CSocketItemEx::DoResend()
{
	const int32_t capacity = pControlBlock->sendBufferBlockN;
	if(! TestAndLockReady())
	{
#ifdef TRACE
		printf_s("\n#0x%X's DoResend not executed due to lack of locks in state %s. InUse: %d\n"
			, fidPair.source, stateNames[lowState], IsInUse());
#endif
		return;
	}
	// TODO: light-weight mutex
	ControlBlock::seq_t seq1 = pControlBlock->sendWindowFirstSN;
	int32_t index1 = pControlBlock->sendWindowHeadPos;
	ControlBlock::PFSP_SocketBuf p = pControlBlock->HeadSend() + index1;
	int32_t n = pControlBlock->CountSentInFlight();	
	timestamp_t tNow = NowUTC();
	register int k;
	for (k = 0; k < n; k++)
	{
		if (!p->GetFlag<IS_COMPLETED>())	// due to parallism the last 'gap' may include imcomplete buffered data
		{
#ifdef TRACE
			printf_s("Imcomplete packet: SN = %u, index position = %d\n", seq1, index1);
#endif
			break;
		}
		//
		if (p->GetFlag<IS_ACKNOWLEDGED>())	// Normally it's redundant to check the flag but it makes the implementation robust
			pControlBlock->SlideSendWindowByOne();
		else if( (tNow - p->timeSent) < (tRoundTrip_us << 2))	// retransmission time-out is hard coded to 4RTT
			break;
		else if(!EmitWithICC(p, seq1))
			break;
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

	if(k < n)
	{
		resendTimer = NULL;
		AddResendTimer(uint32_t((tRoundTrip_us  - ((tNow - p->timeSent) >> 2)) >> 8));
	}

	SetReady();
}



// Send the selective negative acknowledgement on laziness timed-out
void CSocketItemEx::LazilySendSNACK()
{
	if(! TestAndLockReady())
	{
#ifdef TRACE
		printf_s("\n#0x%X's LazilySendSNACK not executed due to lack of locks in state %s. InUse: %d\n"
			, fidPair.source, stateNames[lowState], IsInUse());
#endif
		return;
	}

	// A COMMIT packet may trigger an instant ACK_FLUSH and make the lazy KEEP_ALIVE obsolete
	if(!InState(ESTABLISHED) && !InState(COMMITTING) && !InState(COMMITTED))
	{
#ifdef TRACE
		printf_s("\n#0x%X's LazilySendSNACK not executed due to it has migrated to state %s.\n"
			, fidPair.source, stateNames[lowState]);
#endif
		goto l_done;
	}

	ALIGN(16)
	struct
	{
		FSP_NormalPacketHeader	hdr;
		FSP_PreparedKEEP_ALIVE	snack;
	} buf2;	// a buffer with two headers

	ControlBlock::seq_t	snKeepAliveExp;
	LONG len = GenerateSNACK(buf2.snack, snKeepAliveExp, sizeof(FSP_NormalPacketHeader));
	assert(len < 0 || len >= sizeof(FSP_NormalPacketHeader) + sizeof(FSP_SelectiveNACK));
	if (len < 0)
	{
		printf_s("Fatal error %d encountered when generate SNACK\n", len);
		goto l_done;
	}
#if defined(TRACE) && (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("LazilySendSNACK local fiber#0x%X\n"
		"\tAcknowledged seq#%u, keep-alive header size = %d\n"
		, fidPair.source
		, snKeepAliveExp
		, len);
#endif

	buf2.hdr.Set(KEEP_ALIVE, (uint16_t)len
		, pControlBlock->sendWindowNextSN - 1
		, snKeepAliveExp
		, pControlBlock->RecvWindowSize());
	SetIntegrityCheckCode(&buf2.hdr, NULL, 0, buf2.snack.GetSaltValue());
#if defined(TRACE) && (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("To send KEEP_ALIVE seq #%u, acknowledge #%u, source ALFID = 0x%X\n"
		, be32toh(buf2.hdr.sequenceNo)
		, snKeepAliveExp
		, fidPair.source);
	printf_s("KEEP_ALIVE total header length: %d, should be payloadless\n", len);
	DumpNetworkUInt16((uint16_t *)& buf2, len / 2);
#endif
	SendPacket(1, ScatteredSendBuffers(&buf2, len));

l_done:
	lazyAckTimer = NULL;
	SetReady();
}



// Do
//	Send the KEEP_ALIVE packet, which support mobility, multi-home and selective negative acknowledgement
// Return
//	true if KEEP_ALIVE was sent successfully
//	false if send was failed
bool CSocketItemEx::SendKeepAlive()
{
	ALIGN(16)
		struct
	{
		FSP_NormalPacketHeader	hdr;
		FSP_ConnectParam		mp;
		FSP_PreparedKEEP_ALIVE	snack;
	} buf3;	// a buffer with three headers
	FSP_ConnectParam &mp = buf3.mp;	// this alias make the code a little concise

	u_int k = CLowerInterface::Singleton()->sdSet.fd_count;
	u_int j = 0;
	LONG w = CLowerInterface::Singleton()->disableFlags;
	for (register u_int i = 0; i < k; i++)
	{
		if (!BitTest(&w, i))
		{
			mp.subnets[j++] = SOCKADDR_SUBNET(&CLowerInterface::Singleton()->addresses[i]);
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
	mp.idHost = SOCKADDR_HOSTID(&CLowerInterface::Singleton()->addresses[0]);
	mp.hs.Set(PEER_SUBNETS, sizeof(FSP_NormalPacketHeader));

	ControlBlock::seq_t	snKeepAliveExp;
	LONG len = GenerateSNACK(buf3.snack, snKeepAliveExp, sizeof(FSP_NormalPacketHeader) + sizeof(FSP_ConnectParam));
	if (len < 0)
	{
		printf_s("Fatal error %d encountered when generate SNACK\n", len);
		return false;
	}
#if defined(TRACE) && (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("Keep-alive local fiber#0x%X\n"
		"\tAcknowledged seq#%u, keep-alive header size = %d\n"
		, fidPair.source
		, snKeepAliveExp
		, len);
#endif

	buf3.hdr.Set(KEEP_ALIVE, (uint16_t)len
		, pControlBlock->sendWindowNextSN - 1
		, snKeepAliveExp
		, pControlBlock->RecvWindowSize());
	SetIntegrityCheckCode(&buf3.hdr, NULL, 0, buf3.snack.GetSaltValue());
#if defined(TRACE) && (TRACE & (TRACE_HEARTBEAT | TRACE_PACKET | TRACE_SLIDEWIN))
	printf_s("To send KEEP_ALIVE seq #%u, acknowledge #%u, source ALFID = 0x%X\n"
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
	printf_s("Acknowledge flush: local fiber#0x%X\tAcknowledged seq#%u\n"
		, fidPair.source
		, pControlBlock->recvWindowNextSN);
#endif

	buf2.hdr.Set(ACK_FLUSH, (uint16_t)sizeof(buf2)
		, pControlBlock->sendWindowNextSN - 1
		, pControlBlock->recvWindowNextSN
		, pControlBlock->RecvWindowSize());
	SetIntegrityCheckCode(&buf2.hdr, NULL, 0, buf2.snack.serialNo);
	return SendPacket(1, ScatteredSendBuffers(&buf2, sizeof(buf2))) > 0;
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
//	Milky payload might be retansmitted on demand, but it isn't implemented here
//  It is an accumulative acknowledgment if n == 0
//	Memory integrity is checked here as well
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
		TRACE_HERE("memory overflow");
		printf_s("Given memory size: %d, wanted limit: %zd\n"
			, dwMemorySize
			, sizeof(ControlBlock) + (sizeof(ControlBlock::FSP_SocketBuf) + MAX_BLOCK_SIZE) * capacity);
#endif
		return -EFAULT;
	}

	const int sentWidth = pControlBlock->CountSentInFlight();
	if (sentWidth < 0)
	{
		TRACE_HERE("send queue internal state error");
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

	if(nAck > 0)
		RecalibrateRTT(rtt64_us);
	// ONLY when the first packet in the send window is acknowledged may round-trip time re-calibrated
	// We assume that after sliding send window the number of unacknowledged was reduced
	if(pControlBlock->GetSendQueueHead()->GetFlag<IS_ACKNOWLEDGED>())
		pControlBlock->SlideSendWindow();

	return nAck;
}
