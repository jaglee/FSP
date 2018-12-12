#pragma once
/*
 * The congestion manager sublayer for FSP concept implementation
 * Rate-control based, depend on explicit congestion notification 
 *
	Copyright (c) 2018, Jason Gao
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

// Unlike RFC3124, the congestion manager sublayer of FSP implementation is not stateful
// but instead works like the memory cache that drops out the Least Recently Used item 
// on demand.
// See also RFC2292, Advanced Sockets API for IPv6
#include "../FSP_Impl.h"

// See also struct FSP_IN6_ADDR and struct FSP_SINKINFO
typedef struct AggregatedFlowIdForCongestionManager
{
	union
	{
		FSP_IN4_ADDR_PREFIX _6to4;
		uint64_t	subnet;
	};
	octet			isMIND;			// Traffic Class actually, 0 for best effort, 1 for MINimal Delay
	uint32_t		ipi6_ifindex;	// Different path with multi-homing may have different congestion experience
} * PAFlowId;	// Pointer to aggregated flow Id

#ifdef __cplusplus
extern "C"
{
#endif

	// Given
	//	PAFlowId	The aggregated flow id for congestion management
	//	size_t		number of octets received
	//	size_t		number of octets suspected to be lost
	//	uint64_t	round-trip time, in microseconds
	// Return
	//	0: no error
	//	negative: the error number
	// Remark
	//	usually called on non-transmitted packet acknowledged
	int cm_update(PAFlowId, size_t, size_t, uint64_t);
	
	// Given
	//	PAFlowId	The aggregated flow id for congestion management
	// Return
	//	0: no error
	//	negative: the error number
	// Remark
	//	usually called on a packet piggybacking ECE flag received
	int cm_ECE_received(PAFlowId);

	// Given
	//	PAFlowId	The aggregated flow id for congestion management
	//	int32_t		Number of octets indent to send
	// Return
	//	positive: number of octets allowable to send
	//	negative: the error number. cannot send
	int cm_query_quota(PAFlowId, int32_t);
#ifdef __cplusplus
}
#endif


// The simple hash algorithm. FNV or xxhash might be better
// https://en.wikipedia.org/wiki/List_of_prime_numbers
const int32_t primeLimit = 251;
int32_t HashFlowId(PAFlowId s)
{
	int32_t a = 71;
	for (register int i = 0; i < sizeof(struct AggregatedFlowIdForCongestionManager); i++)
	{
		a ^= ((octet *)s)[i];
		a %= primeLimit;
	}
}

static struct SAFlowCongestionDescriptorEntry
{
	struct AggregatedFlowIdForCongestionManager idFlow;
	int64_t quotaRemained;
} cmEntries[primeLimit];
