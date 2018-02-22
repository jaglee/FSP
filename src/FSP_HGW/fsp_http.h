/*
 * Simple HTTP 1.0 server over FSP version 0. SOCKS gateway and tunnel server as well
 * The definitions of the service-side session related classes
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

#include "defs.h"
#include "../Crypto/CHAKA.h"

struct LineBuffer
{
	int		firstOffset;
	int		lastOffset;
	char	buf[BUFFER_POOL_SIZE];
};


const octet sampleSalt[CRYPTO_SALT_LENGTH] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
const char *samplePassword = "Passw0rd";

// Definition of pointer to Flexible Session Associated Data
// We make sure it may be safely casted to LineBuffer *
typedef struct AssociatedData: LineBuffer
{
	SCHAKAPublicInfo chakaPubInfo;
	octet sessionClientIdString[_MAX_PATH];
	octet salt[CRYPTO_SALT_LENGTH];
	octet passwordHash[CRYPTO_NACL_HASHBYTES];
	octet bufSharedKey[CRYPTO_NACL_KEYBYTES];
} *PFSAData;


// Server side forward declarations
int	FSPAPI onMultiplying(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);
void ReportToRemoteClient(PRequestPoolItem, ERepCode);

