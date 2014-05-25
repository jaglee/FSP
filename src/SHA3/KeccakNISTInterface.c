/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michaël Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by the designers,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

2014.06.21 Updated by Jason Gao to make it compatible with the NIST SHA3 draft edition
*/

#include <string.h>
#include "KeccakNISTInterface.h"
#include "KeccakF-1600-interface.h"

HashReturn Init(hashState *state, int hashbitlen)
{
	KeccakF1600_Initialize();
    switch(hashbitlen) {
        case 0:	// by default 
			Keccak_HashInitialize_SHAKE256(state);
            break;
		case 128:
			Keccak_HashInitialize_SHAKE128(state);
			break;
        case 224:
			Keccak_HashInitialize_SHA3_224(state);
            break;
        case 256:
			Keccak_HashInitialize_SHA3_256(state);
            break;
        case 384:
			Keccak_HashInitialize_SHA3_384(state);
			break;
        case 512:
			Keccak_HashInitialize_SHA3_512(state);
			break;
        default:
            return BAD_HASHLEN;
    }
    state->fixedOutputLength = hashbitlen;
    return SUCCESS;
}


HashReturn Final(hashState *state, BitSequence *hashval)
{
	Keccak_HashFinal(state, hashval);
	return Keccak_HashSqueeze(state, hashval, state->fixedOutputLength);
}


HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
    hashState state;
    HashReturn result;

    result = Init(&state, hashbitlen);
    if (result != SUCCESS)
        return result;
    result = Update(&state, data, databitlen);
    if (result != SUCCESS)
        return result;
    result = Final(&state, hashval);
    return result;
}
