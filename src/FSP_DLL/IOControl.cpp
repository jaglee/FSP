/*
 * DLL to service FSP upper layer application
 * I/O control functions to get/set session parameters
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
#include "FSP_DLL.h"


// When use FSPControl to enumerate interfaces,
// 'value' is the pointer to the first element of an array of IN6_PKTINFO structure
// and the 'ipi6_ifindex' field of the first element should store the size of the array
// return number of available interfaces with configured IPv4/IPv6 address
// which might be zero. negative if error.




// Given
//	FSPHANDLE			the handle to the FSP socket
//	FSP_ControlCode		the code of the control point
//	ULONG_PTR			the value to be set
// Do
//	Set the value of the control point designated by the code
// Return
//	0 if no error
//	-EDOM if some parameter is out of scope
//	-EINTR if exception thrown
DllExport
int FSPAPI FSPControl(FSPHANDLE hFSPSocket, FSP_ControlCode controlCode, ULONG_PTR value)
{
	try
	{
		CSocketItemDl *pSocket = (CSocketItemDl *)hFSPSocket;
		switch(controlCode)
		{
		case FSP_GET_EXT_POINTER:
			*(ULONG_PTR *)value = (ULONG_PTR)pSocket->GetULASignature();
			break;
		case FSP_SET_EXT_POINTER:
			pSocket->SetULASignature(value);
			break;
		case FSP_SET_CALLBACK_ON_ERROR:
			pSocket->SetCallbackOnError((NotifyOrReturn)value);
			break;
		case FSP_SET_CALLBACK_ON_REQUEST:
			pSocket->SetCallbackOnRequest((CallbackRequested)value);
			break;
		case FSP_SET_CALLBACK_ON_CONNECT:
			pSocket->SetCallbackOnAccept((CallbackConnected)value);
			break;
		case FSP_GET_PEER_COMMITTED:
			*((int *)value) = pSocket->HasPeerCommitted() ? 1 : 0;
			break;
		default:
			return -EDOM;
		}
		return 0;
	}
	catch(...)
	{
		return -EINTR;
	}
}


/*
 * FSP LZ4 frame format
 * Start of the first frame MUST be aligned with start of the transmit transaction
 * Magic Number AND version identifier: 4 octet, FSLZ
 * each block depends on previous ones (up to LZ4 window size, which is 64KB)
 * it's necessary to decode all blocks in sequence
 * block max size is fixed in each version
 * no header checksum
 * Little endian, 3 octet
 * Data blocks: block size [4 bytes], data
 * The algorithm:
 */

#define FSP_MAX_SEGMENT_SIZE (1 << 17)	// 128KB
#define LZ4_DICTIONARY_SIZE (1 << 16)

#include <pshpack1.h>
struct CSocketItemDl::SStreamState
{
	LZ4_stream_t	streamState;
	//
	ALIGN(8)
	int32_t		rNext;		// buffered but not compressed, the ring buffer
	int32_t		dstNext;	// first available byte in the target buffer, following the ring buffer
	int32_t		srcDstNext;	// the target buffer as source - to copy out
	int32_t		outSize;	// number of bytes output by compression
	int8_t		rHeader;	// number of header bytes that remains to be output
	int32_t		limit;		// capacity of the output buffer
	//
	octet		dictBuf[LZ4_DICTIONARY_SIZE];
	octet		inBuf[FSP_MAX_SEGMENT_SIZE];
	// The output buffer follows inBuf, its capacity is dynamically calculated

	// Return number of octets actually copied
	int32_t CopyIn(const void *srcBuf, int32_t n)
	{
		n = min(n, int32_t(sizeof(inBuf) - rNext));
		memcpy(inBuf + rNext, srcBuf, n);
		rNext += n;
		return n;
	}
	// Return number of octets actually copied. Should equal to tgtSize
	int32_t CopyOut(void *tgtBuf, int32_t tgtSize)
	{
		register int32_t n = tgtSize;
		if(rHeader > 0)
		{
			register int32_t m = min(rHeader, n);
			memcpy(tgtBuf, (octet *) & outSize + sizeof(outSize) - rHeader, m);
			if((rHeader -= m) > 0)
				return m;	// assert: m == tgtSize
			//
			n -= m;
			tgtBuf = (octet *)tgtBuf + m;
		}
		memcpy(tgtBuf, inBuf + sizeof(inBuf) + srcDstNext, n);
		srcDstNext += n;
		return tgtSize;
	}
	//
	int32_t ForcefullyCompress();
};



struct CSocketItemDl::SDecodeState
{
	LZ4_streamDecode_t decodeState;
	//
	ALIGN(8)
	int32_t		dNext;		// data buffer, the ring buffer
	int8_t		nbHeader;	// number of header bytes that had been read
	int8_t		needData;
	int8_t		isDictFull;
	int32_t		dstNext;	// the compressed source, copy-in
	int32_t		srcDstNext;	// the source to be decoded
	int32_t		compressedSize;
	int32_t		limit;
	//
	octet		dictBuf[LZ4_DICTIONARY_SIZE];
	octet		outBuf[LZ4_DICTIONARY_SIZE + FSP_MAX_SEGMENT_SIZE];
	// The input buffer follows outBuf, its size is dynamically calculated

	// Assume it is little-endian, needn't transform uint32_t for x86/amd64/IA64 CPU
	// return number of octets actually consumed
	int32_t GetMetadata(const void *srcBuf, int32_t n)
	{
		n = min(n, (int32_t)sizeof(compressedSize) - nbHeader);
		memcpy((octet *)& compressedSize + nbHeader, srcBuf, n);
		//
		nbHeader += n;
		if(nbHeader < sizeof(compressedSize))
			return n;
		//
		if (compressedSize <= 0 || compressedSize > limit)
			return -EFAULT;
		//
		needData = 1;
		return n;
	}
	// return number of octets actually copied
	int32_t CopyIn(const void *srcBuf, int32_t n)
	{
		n = min(n, limit - dNext);
		if(n <= 0)
			return -EFAULT;
		memcpy(outBuf + sizeof(outBuf) + dNext, srcBuf, n);
		dNext += n;
		if(dNext >= compressedSize)
			needData = 0;
		return n;
	}
	// return number of octets actually copied
	int32_t	CopyOut(void *tgtBuf, int32_t tgtSize)
	{
		tgtSize = min(dstNext - srcDstNext, tgtSize);
		memcpy(tgtBuf, outBuf + srcDstNext, tgtSize);
		srcDstNext += tgtSize;
		return tgtSize;
	}
	//
	int32_t Decompress();
};
#include <poppack.h>


// return number of output octets
int32_t CSocketItemDl::SStreamState::ForcefullyCompress()
{
	int	messageSize = min(rNext, FSP_MAX_SEGMENT_SIZE);
	if(messageSize == 0)
		return 0;

	// Make the output buffer leave room for new result
	// assert: srcDstNext == dstNext
	if(dstNext > 0)
	{
		LZ4_saveDict(& streamState, (char *)dictBuf, sizeof(dictBuf));
		srcDstNext = dstNext = 0;
	}
	//
	outSize = LZ4_compress_fast_continue(& streamState, (char *)inBuf
			, (char *)inBuf + sizeof(inBuf)
			, messageSize
			, limit
			, 1);
	rNext = 0;
	if(outSize <= 0)
		return outSize;
	rHeader = sizeof(outSize);
	dstNext += outSize;
	return outSize + rHeader;
}



// assert: pCtx->srcDstNext == pCtx->dstNext && needData == 0
// return number of output octets
int32_t CSocketItemDl::SDecodeState::Decompress()
{
	if(dstNext > LZ4_DICTIONARY_SIZE)
	{
		memcpy(dictBuf, outBuf + dstNext - LZ4_DICTIONARY_SIZE, LZ4_DICTIONARY_SIZE); 
		LZ4_setStreamDecode(& decodeState, (char *)dictBuf, LZ4_DICTIONARY_SIZE);
		srcDstNext = dstNext = 0;
		isDictFull = 1;
	}
	else if(isDictFull && dstNext > 0)
	{
		memmove(dictBuf, dictBuf + LZ4_DICTIONARY_SIZE - dstNext, LZ4_DICTIONARY_SIZE - dstNext);
		memcpy(dictBuf + LZ4_DICTIONARY_SIZE - dstNext, outBuf, dstNext);
		LZ4_setStreamDecode(& decodeState, (char *)dictBuf, LZ4_DICTIONARY_SIZE);
	}

	// here the input buffer instantly follows outBuf
	dNext -= compressedSize;
	if(dNext < 0)
		return -EFAULT;
	int k = LZ4_decompress_safe_continue(& decodeState
		, (char *) & outBuf + sizeof(outBuf)
		, (char *) & outBuf + dstNext
		, compressedSize
		, limit - dstNext);
	if(k <= 0)
		return k;
	//
	octet *pNext = outBuf + sizeof(outBuf) + compressedSize;
	// needData = 0;
	if(0 < dNext && dNext < sizeof(compressedSize))
	{
		memcpy(& compressedSize, pNext, nbHeader = dNext);
		dNext = 0;
	}
	else if(0 < dNext)
	{
		memcpy(& compressedSize, pNext, nbHeader = sizeof(compressedSize));
		dNext -= sizeof(compressedSize);
		needData = 1;
		memmove(outBuf + sizeof(outBuf), pNext + sizeof(compressedSize), dNext);
	}
	//
	dstNext += k;
	return k;
}



// Return
//	true if the internal streaming buffer for on-the-wire compression has been prepared
//	false if no memory
// Remark
//	The buffer shall be free as soon as the transmit transaction is committed by the near end
bool CSocketItemDl::AllocStreamState()
{
	if(pStreamState != NULL)
		return true;

	int n = LZ4_compressBound(FSP_MAX_SEGMENT_SIZE);
	pStreamState = (CSocketItemDl::SStreamState *)
		malloc(sizeof(CSocketItemDl::SStreamState) + sizeof(uint32_t) + n);
	if(pStreamState == NULL)
		return false;
	//
	pStreamState->limit = n;
	memset(& pStreamState->rNext, 0, (octet *) & pStreamState->limit - (octet *) & pStreamState->rNext);
	LZ4_resetStream(& pStreamState->streamState);
	return true;
}



// Return
//	true if the internal decoding buffer for on-the-wire decompression has been prepared
//	false if no memory
// Remark
//	The buffer shall be free as soon as the transmit transaction is committed by the remote end
bool CSocketItemDl::AllocDecodeState()
{
	if(pDecodeState != NULL)
		return true;

	int n = LZ4_compressBound(FSP_MAX_SEGMENT_SIZE);
	pDecodeState = (CSocketItemDl::SDecodeState *)
		malloc(sizeof(CSocketItemDl::SDecodeState) + n);
	if(pDecodeState == NULL)
		return false;

	memset(& pDecodeState->dNext, 0, (octet *) & pDecodeState->limit - (octet *) & pDecodeState->dNext);
	LZ4_setStreamDecode(& pDecodeState->decodeState, NULL, 0);
	pDecodeState->limit = n;
	return true;
}



// Given
//	void *			Target buffer
//	int &			[_InOut_] In: the capacity of the target buffer, Out: number of bytes occupied
//	const void *	Source buffer
//	int				length of the source octet string
// Return
//	Number of octets consumed from the source
// Remark
//	The source octet string is automatically segmented
//	If the given length of the source octet string is zero,
//	the source buffer should be null and the internal buffer is meant to be flushed.
int	CSocketItemDl::Compress(void *pOut, int &tgtSize, const void *pIn, int srcLen)
{
	register SStreamState *pCtx = pStreamState;
	if(tgtSize <= 0)
		return 0;
	// Firstly, check whether the buffered compressed data has more data to deliver. If it does, return the data
	if (pendingStreamingSize > 0)
	{
		tgtSize = pCtx->CopyOut(pOut, min(tgtSize, pendingStreamingSize));
		pendingStreamingSize -= tgtSize;
		return 0;	// the uncompressed data is not consumed.
	}

	// now pendingStreamingSize == 0, pCtx->dstNext == pCtx->srcDstNext
	// firstly, try to copy in more data
	int nbCopyIn = srcLen;
	if (nbCopyIn > 0)
		nbCopyIn = pCtx->CopyIn(pIn, nbCopyIn);

	// The last segment of the transaction, or the one has been fulfilled should be compressed
	if(srcLen == 0 || pCtx->rNext >= FSP_MAX_SEGMENT_SIZE)
	{
		pendingStreamingSize = pCtx->ForcefullyCompress();
		if(pendingStreamingSize <= 0)
		{
			tgtSize = 0;
			return pendingStreamingSize;
		}		
	}

	tgtSize = min(tgtSize, pendingStreamingSize);
	if(tgtSize > 0)
		pendingStreamingSize -= pCtx->CopyOut(pOut, tgtSize);

	return nbCopyIn;
}


// Return whether internal buffer for compression is empty
bool CSocketItemDl::HasDataToCommit()
{
	return (pendingSendSize > 0 || pStreamState != NULL && (pendingStreamingSize > 0 || pStreamState->rNext > 0));
}


// Given
//	void *			Target buffer
//	int &			[_InOut_] In: the capacity of the target buffer, Out: number of bytes occupied
//	const void *	Source buffer
//	int				length of the source octet string
// Remark
//	The frame border of the source octet string [the compressed result] is automatically detected
//	Previously decoded blocks *must* remain available at the memory position where they were decoded (up to 64 KB)
int	CSocketItemDl::Decompress(void *pOut, int &tgtSize, const void *pIn, int srcLen)
{
	register CSocketItemDl::SDecodeState *pCtx = pDecodeState;
	if(tgtSize <= 0)
		return 0;

	// Firstly, check whether the buffered decompressed data has more data to deliver. If it does, return the data
	if (pCtx->dstNext - pCtx->srcDstNext > 0)
	{
		tgtSize = pCtx->CopyOut(pOut, tgtSize);
		return 0;	// the uncompressed data is not consumed.
	}

	if(srcLen <= 0)
	{
		tgtSize = 0;
		return 0;	// both the source and the internal buffer is empty
	}

	int overhead = 0;
	if (! pCtx->needData)
	{
		overhead = pCtx->GetMetadata(pIn, srcLen);
		if(overhead < 0 || ! pCtx->needData)
		{
			tgtSize = 0;
			return overhead;
		}
		//
		pIn = (octet *)pIn + overhead;
		srcLen -= overhead;
	}

	// Now pCtx->nToCopyIn > 0 && srcLen > 0
	int n = pCtx->CopyIn(pIn, srcLen);
	if (pCtx->needData)
	{
		tgtSize = 0;
		return n + overhead;
	}

	// Now it's time to decompress
	int k = pCtx->Decompress();
	if(k < 0)
		return k;

	tgtSize = pCtx->CopyOut(pOut, tgtSize);
	return n + overhead;
}



// Return true if the internal buffer is empty, false if it is not.
bool CSocketItemDl::FlushDecodeState()
{
	if(pDecodeState == NULL)
		return true;

	for(int k = waitingRecvSize; k > 0; k = waitingRecvSize)
	{
		Decompress(waitingRecvBuf, k, NULL, 0);
		if(k < 0)
			return false;
		if(k == 0)
			break;
		waitingRecvBuf += k;
		waitingRecvSize -= k;
	}
	// it is both safe and more reliable to check the internal buffer directly
	if(pDecodeState->dstNext - pDecodeState->srcDstNext > 0)
	{
		peerCommitPending |= peerCommitted;
		peerCommitted = 0;
		return false;
	}

	peerCommitted |= peerCommitPending;
	free(pDecodeState);
	pDecodeState = NULL;
	return true;
}
