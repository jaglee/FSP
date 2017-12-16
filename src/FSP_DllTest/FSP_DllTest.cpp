// FSP_DllUnitTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

const ControlBlock::seq_t FIRST_SN = 12;

// See also CSocketItemDl::Connect2
CSocketItemDbg *GetPreparedSocket(int32_t minSendBufSize = 0)
{
	static CommandNewSession objCommand;
	static FSP_SocketParameter parms;
	memset(& parms, sizeof(parms), 0);
	parms.onAccepting = NULL;
	parms.onAccepted = NULL;
	parms.onError = NULL;
	parms.recvSize = MAX_FSP_SHM_SIZE - minSendBufSize;		// 4MB
	parms.sendSize = minSendBufSize;	// the underlying service would give the minimum, however
	parms.passive = 0;	// override what is provided by ULA
	parms.welcome = NULL;	// an active connection request shall have no welcome message
	parms.len = 0;			// or else memory access exception may occur

	IN6_ADDR addrAny = IN6ADDR_ANY_INIT;
	return (CSocketItemDbg *)CSocketItemDl::CreateControlBlock((PFSP_IN6_ADDR) & addrAny, & parms, objCommand);
}


//
static void FUZ_fillCompressibleNoiseBuffer(void* buffer, size_t bufferSize, double proba, U32 * seed);


void UnitTestCheckedRevertCommit()
{
	CSocketItemDbg *pSocketItem = GetPreparedSocket();
	ControlBlock *pSCB = pSocketItem->GetControlBlock();
	bool flag = false;

	pSCB->state = NON_EXISTENT;
	int r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);

	pSCB->state = CONNECT_BOOTSTRAP;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);

	pSCB->state = PRE_CLOSED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);

	pSCB->state = CLOSED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);
	//

	pSCB->state = COMMITTING;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == -EBUSY);

	pSCB->state = COMMITTING2;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == -EBUSY);

	pSCB->state = COMMITTED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 1 && pSCB->state == ESTABLISHED);

	pSCB->state = CLOSABLE;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 1 && pSCB->state == PEER_COMMIT);

	//
	pSCB->state = CONNECT_AFFIRMING;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	pSCB->state = ESTABLISHED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	pSCB->state = PEER_COMMIT;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	pSCB->state = CLONING;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	//
	// LISTENING state is just ignored
	//
	pSCB->state = NON_EXISTENT;

	//
	//
	//
	pSCB->state = NON_EXISTENT;
	flag = true;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);

	pSCB->state = CONNECT_BOOTSTRAP;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);

	pSCB->state = PRE_CLOSED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);

	pSCB->state = CLOSED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r < 0);
	//

	pSCB->state = COMMITTING;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == -EBUSY);

	pSCB->state = COMMITTING2;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == -EBUSY);

	pSCB->state = COMMITTED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 1 && pSCB->state == COMMITTING);

	pSCB->state = CLOSABLE;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 1 && pSCB->state == COMMITTING2);

	//
	pSCB->state = CONNECT_AFFIRMING;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	pSCB->state = ESTABLISHED;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	pSCB->state = PEER_COMMIT;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);

	pSCB->state = CLONING;
	r = pSocketItem->CheckTransmitaction(flag);
	assert(r == 0);
}



// Test logic of SendStream and SendInplace
void UnitTestBufferData()
{
	CSocketItemDbg *pSocketItem = GetPreparedSocket();
	ControlBlock *pSCB = pSocketItem->GetControlBlock();
	//
	static BYTE preparedTestData[MIN_RESERVED_BUF + MAX_BLOCK_SIZE]; // well, the last block is actually not used yet
	for(register int i = 0; i < sizeof(preparedTestData); i += 2)
	{
		*(short *)(preparedTestData + i) = (short)i;
	}
	//
	pSCB->state = ESTABLISHED;
	pSCB->SetRecvWindow(FIRST_SN);
	pSCB->SetSendWindow(FIRST_SN);
	printf_s("Buffer next SN = %u\n", pSCB->sendBufferNextSN);
	//
	// Emulate SendStream()
	//
	pSocketItem->SetState(ESTABLISHED);
	pSocketItem->CheckTransmitaction(0);
	pSocketItem->pendingSendBuf = preparedTestData;
	pSocketItem->BufferData(MIN_RESERVED_BUF - 2);
	printf_s("Buffer next SN = %u\n", pSCB->sendBufferNextSN);
	assert(pSCB->sendBufferNextSN == FIRST_SN + MIN_RESERVED_BUF / MAX_BLOCK_SIZE);
	//
	// As the last buffered data is incomplete sent data is pending at the tail of the last block
	//
	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadSend();
	BYTE *buf = pSocketItem->GetSendPtr(skb);
	int r;
	for(register int i = 0; i < (MIN_RESERVED_BUF - 2) / 2; i += 2)
	{
		if(*(short *)(preparedTestData + i) != *(short *)(buf + i))
			printf_s("Short#%d differs\n", i);
	}

	// Now, reset, but this time the head packet is set
	pSCB->SetSendWindow(FIRST_SN);
	pSocketItem->SetEndTransaction();
	pSocketItem->SetHeadPacketIfEmpty(PERSIST);

	// now, there was no enough buffer and the data were partly buffered
	pSocketItem->pendingSendBuf = preparedTestData;
	r = pSocketItem->BufferData(MIN_RESERVED_BUF - 2);
	printf_s("%d packets completed, %d octets remains\n", r, pSocketItem->pendingSendSize);
	printf_s("Buffer next SN = %u\n", pSCB->sendBufferNextSN);
	assert(pSCB->sendBufferNextSN == FIRST_SN + MIN_RESERVED_BUF / MAX_BLOCK_SIZE);
	//
	// Now, slide the send window, and leave one more slot for sending
	//
	pSCB->SlideSendWindowByOne();
	pSocketItem->BufferData(pSocketItem->pendingSendSize);
	printf_s("Buffer next SN = %u\n", pSCB->sendBufferNextSN);
	assert(pSCB->sendBufferNextSN == FIRST_SN + MIN_RESERVED_BUF / MAX_BLOCK_SIZE + 1);
	//
	// As there are only two blocks for MIN_RESERVED_BUF...Round-robin tested
	//
	skb = pSCB->HeadSend() + 1;
	buf = pSocketItem->GetSendPtr(skb);
	for(register int i = 0; i < MAX_BLOCK_SIZE; i += 2)
	{
		printf_s("%04x_%04x   ", *(short *)(preparedTestData + i), *(short *)(buf + i));
		if(i % 10 == 8)
			printf_s("\n");
		//
		assert(*(short *)(preparedTestData + i) == *(short *)(buf + i));
	}
	printf_s("\n====\n");
	//
	buf = pSocketItem->GetSendPtr(pSCB->HeadSend());
	for(register int i = 0; i < MAX_BLOCK_SIZE - 2; i += 2)
	{
		printf_s("%04x_%04x   ", *(short *)(preparedTestData + MAX_BLOCK_SIZE + i), *(short *)(buf + i));
		if(i % 10 == 8)
			printf_s("\n");
		//
		assert(*(short *)(preparedTestData + MAX_BLOCK_SIZE + i) == *(short *)(buf + i));
	}
	printf_s("\n\n");

	//
	// Try on-the-wire compression
	//
	// But a payload less PERSIST is treated specially: it may carry no compressed flag
	pSCB->SetSendWindow(FIRST_SN);
	pSocketItem->SetHeadPacketIfEmpty(PERSIST);
	bool successful = pSocketItem->AllocStreamState();
	assert(successful);

	// Now, make it deeply compressible
	for(register int i = 0; i < sizeof(preparedTestData); i += 2)
	{
		*(short *)(preparedTestData + i) = (short)(octet)i;
	}

	pSocketItem->pendingSendBuf = preparedTestData;
	pSocketItem->SetEndTransaction();
	pSocketItem->bytesBuffered = 0;
	r = pSocketItem->BufferData(MIN_RESERVED_BUF - 2);
	// assert: pSocketItem->pStreamState == NULL;
	printf_s("%d packets completed, %d octets remains, %d internally buffered\n"
		, r, pSocketItem->pendingSendSize, pSocketItem->pendingStreamingSize);
	printf_s("Buffer next SN = %u\n", pSCB->sendBufferNextSN);

	// Pretend that all the data packet have been received:
	memcpy(pSCB->GetRecvPtr(pSCB->HeadRecv()), pSCB->GetSendPtr(pSCB->HeadSend()), MIN_RESERVED_BUF - 2);
	while(int(pSCB->recvWindowNextSN - pSCB->sendBufferNextSN) < 0)
	{
		ControlBlock::PFSP_SocketBuf skb1 = pSCB->HeadSend() + (pSCB->recvWindowNextSN - FIRST_SN);
		ControlBlock::PFSP_SocketBuf skb = pSCB->AllocRecvBuf(pSCB->recvWindowNextSN);
		*skb = *skb1;
	}

	// Decompress
	buf = (BYTE *)_alloca(MIN_RESERVED_BUF);
	pSocketItem->waitingRecvSize = MIN_RESERVED_BUF;
	pSocketItem->waitingRecvBuf = buf;
	pSocketItem->bytesReceived = 0;
	pSocketItem->FetchReceived();
	r = memcmp(buf, preparedTestData, MIN_RESERVED_BUF - 2);
	assert(r == 0);

	// Now, cross buffer
	// Reset again
	successful = pSocketItem->AllocStreamState();
	assert(successful);
	pSCB->SetSendWindow(FIRST_SN);
	pSCB->SetRecvWindow(FIRST_SN);

	uint32_t randValue;
	FUZ_fillCompressibleNoiseBuffer(preparedTestData, MIN_RESERVED_BUF, 0.5, &randValue);

	pSocketItem->pendingSendBuf = preparedTestData;
	pSocketItem->SetEndTransaction();
	pSocketItem->bytesBuffered = 0;
	r = pSocketItem->BufferData(MIN_RESERVED_BUF - 2);
	printf_s("%d packets completed, %d octets remains, %d internally buffered\n"
		, r, pSocketItem->pendingSendSize, pSocketItem->pendingStreamingSize);
	printf_s("Buffer next SN = %u\n", pSCB->sendBufferNextSN);

	// Pretend that all the data packet have been received:
	memcpy(pSCB->GetRecvPtr(pSCB->HeadRecv()), pSCB->GetSendPtr(pSCB->HeadSend()), MIN_RESERVED_BUF - 2);
	while(int(pSCB->recvWindowNextSN - pSCB->sendBufferNextSN) < 0)
	{
		ControlBlock::PFSP_SocketBuf skb1 = pSCB->HeadSend() + (pSCB->recvWindowNextSN - FIRST_SN);
		ControlBlock::PFSP_SocketBuf skb = pSCB->AllocRecvBuf(pSCB->recvWindowNextSN);
		*skb = *skb1;
	}

	// Decompress
	pSocketItem->waitingRecvSize = MIN_RESERVED_BUF;
	pSocketItem->waitingRecvBuf = buf;
	pSocketItem->bytesReceived = 0;
	pSocketItem->FetchReceived();
	r = memcmp(buf, preparedTestData, MIN_RESERVED_BUF - 2);
	assert(r == 0);
}


static int ParseBlock(octet *utf8str, int32_t len)
{
	static char partialFileName[sizeof(TCHAR) * MAX_PATH + 4];	// buffered partial file name
	static int lenPartial = 0;					// length of the partial name
	//TCHAR finalFileName[MAX_PATH];
	char finalFileName[MAX_PATH];				// Well, the console is of MBCS
	int lenCurrent = 0;
	int nScanned = 0;

	// Set the sentinel
	char c = utf8str[len - 1];
	utf8str[len - 1] = 0;

	// continue with previous cross-border string
	if (lenPartial > 0)
	{
		while (utf8str[lenCurrent] != 0)
		{
			lenCurrent++;
			nScanned++;
		}
		// There should be a NUL as the string terminator!
		if (c != 0 && lenCurrent >= len)
		{
			printf_s("Attack encountered? File name too long!\n");
			return -1;
		}
		//
		lenCurrent++;	// Make it null-terminated
		nScanned++;
		memcpy(partialFileName + lenPartial, utf8str, lenCurrent);
//#ifdef _MBCS
		UTF8ToLocalMBCS(finalFileName, MAX_PATH, partialFileName);
		printf_s("%s\n", finalFileName);
//#else
//		UTF8ToWideChars(finalFileName, MAX_PATH, partialFileName, lenPartial + lenCurrent);
//		wprintf_s(L"%s\n", finalFileName);
//#endif
		utf8str += lenCurrent;
		lenCurrent = 0;
		lenPartial = 0;
	}
	// A sentinel character is set before scan the input
	do
	{
		while (utf8str[lenCurrent] != 0)
		{
			lenCurrent++;
			nScanned++;
		}
		//
		lenCurrent++;
		nScanned++;
		if (nScanned >= len && c != 0)
		{
			utf8str[lenCurrent - 1] = c;	// so that the sentinel character is copied
			memcpy(partialFileName, utf8str, lenCurrent);
			lenPartial = lenCurrent;
			break;
		}
		//
//#ifdef _MBCS
		UTF8ToLocalMBCS(finalFileName, MAX_PATH, (char *)utf8str);
		printf_s("%s\n", finalFileName);
//#else
//		UTF8ToWideChars(finalFileName, MAX_PATH, (char *)utf8str, lenCurrent);
//		wprintf_s(L"%s\n", finalFileName);
//#endif
		utf8str += lenCurrent;
		lenCurrent = 0;
	} while (nScanned < len);
	//
	return nScanned;
}



// Show the file/sub-directory name of a directory with moderate number of entries
void LogicTestPackedSend()
{
	CSocketItemDbg *pSocketItem = GetPreparedSocket(MAX_FSP_SHM_SIZE / 2);
	ControlBlock *pSCB = pSocketItem->GetControlBlock();
	const TCHAR *pattern = _T("d:\\temp\\*.*");
	octet lineBuf[80];
	char localBuf[80];

	// Emulate that a connection is established
	pSocketItem->SetNewTransaction();
	pSCB->state = ESTABLISHED;
	pSCB->SetRecvWindow(FIRST_SN);
	pSCB->SetSendWindow(FIRST_SN);
	//
	// streaminng into the buffer
	WIN32_FIND_DATA findFileData;
	HANDLE hFind = FindFirstFile(pattern, &findFileData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		_tprintf_s(_T("Directory is empty: %s\n"), pattern);
		return;
	}
#ifdef _MBCS
	return;
#endif
	// Assume it the program was compiled in unicode mode
	do
	{
		// wprintf_s(L"File or directory: %s\n", findFileData.cFileName);
		int nBytes = WideStringToUTF8(lineBuf, sizeof(lineBuf), findFileData.cFileName);
		if (nBytes <= 0)
			continue;
		//
		WriteTo(pSocketItem, lineBuf, nBytes, TO_COMPRESS_STREAM, NULL);
		//
		UTF8ToLocalMBCS(localBuf, sizeof(localBuf), (char *)lineBuf);
		printf_s("File or directory: %s\n", localBuf);
	} while (FindNextFile(hFind, &findFileData));
	//
	FindClose(hFind);
	//
	Commit(pSocketItem, NULL);
	//
	// Pretend that all the data packet have been received:
	memcpy(pSCB->GetRecvPtr(pSCB->HeadRecv()), pSCB->GetSendPtr(pSCB->HeadSend()), pSocketItem->bytesBuffered);
	while (int(pSCB->recvWindowNextSN - pSCB->sendBufferNextSN) < 0)
	{
		ControlBlock::PFSP_SocketBuf skb1 = pSCB->HeadSend() + (pSCB->recvWindowNextSN - FIRST_SN);
		ControlBlock::PFSP_SocketBuf skb = pSCB->AllocRecvBuf(pSCB->recvWindowNextSN);
		*skb = *skb1;
	}
	//
	// Emulate receive (with decompression)
	//
	octet *buf = (octet *)_alloca(MAX_BLOCK_SIZE);
	if (buf == NULL)
		return;
	int n;
	while ((n = ReadFrom(pSocketItem, buf, MAX_BLOCK_SIZE, NULL)) > 0)
	{
		ParseBlock(buf, n);
	}
	//// Receive by calling ReadFrom only once
	//octet *buf = (octet *)malloc(MAX_FSP_SHM_SIZE / 2);
	//if (buf == NULL)
	//	return;
	//int n = ReadFrom(pSocketItem, buf, MAX_FSP_SHM_SIZE / 2, NULL);
	//if (n > 0)
	//	ParseBlock(buf, n);
	////
	//free(buf);
}



//
void UnitTestPrepareToSend()
{
	CSocketItemDbg *pSocketItem = GetPreparedSocket();
	ControlBlock *pSCB = pSocketItem->GetControlBlock();
	//
	pSCB->state = ESTABLISHED;
	pSCB->SetRecvWindow(FIRST_SN);
	pSCB->SetSendWindow(FIRST_SN);
	printf_s("Buffer next SN = %u\n", pSCB->sendBufferNextSN);
	//
	// Emulate SendInplace()
	//
	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadSend();
	BYTE *buf = pSocketItem->GetSendPtr(skb);

	for(register int i = 0; i < MIN_RESERVED_BUF / 2; i += 2)
	{
		*(short *)(buf + i) = (short)i;
	}
	// One packet
	pSocketItem->SetState(ESTABLISHED);
	pSocketItem->SetNewTransaction();
	pSocketItem->PrepareToSend(buf, MAX_BLOCK_SIZE - 2, true);
	assert(pSCB->sendBufferNextSN == FIRST_SN + 1);
	printf_s("Buffer next SN = %u; start packet operation is %s, state is %s\n"
		, pSCB->sendBufferNextSN
		, opCodeStrings[skb->opCode]
		, stateNames[pSocketItem->GetState()]);

	// Reset, two packets
	pSocketItem->SetState(ESTABLISHED);
	pSocketItem->SetNewTransaction();
	pSCB->SetSendWindow(FIRST_SN);
	pSocketItem->PrepareToSend(buf, MIN_RESERVED_BUF - 2, true);
	printf_s("Buffer next SN = %u; start packet operation is %s, state is %s\n\n"
		, pSCB->sendBufferNextSN
		, opCodeStrings[skb->opCode]
		, stateNames[pSocketItem->GetState()]);
}



//
void UnitTestFetchReceived()
{
	CSocketItemDbg *pSocketItem = GetPreparedSocket();	// assume the receive buffer is fulfilled
	ControlBlock *pSCB = pSocketItem->GetControlBlock();
	pSCB->state = ESTABLISHED;
	pSCB->SetRecvWindow(FIRST_SN);
	pSCB->SetSendWindow(FIRST_SN);

	// prepare the receive buffer
	ControlBlock::PFSP_SocketBuf skb = pSCB->HeadRecv();
	BYTE *preparedTestData = pSocketItem->GetRecvPtr(skb);
	for (register int i = 0; i < MAX_FSP_SHM_SIZE; i += sizeof(int))
	{
		*(int *)(preparedTestData + i) = i;
	}

	while ((skb = pSCB->AllocRecvBuf(pSCB->recvWindowNextSN)) != NULL)
	{
		skb->len = MAX_BLOCK_SIZE;
		skb->opCode = PURE_DATA;
		skb->SetFlag<IS_FULFILLED>();
	}
	// pSCB->recvWindowNextSN == pSCB->recvWindowFirstSN + pSCB->recvBufferBlockN;
	// And pSCB->recvWindowNextPos is rounded
	printf_s("After initialization, receive next SN = %u\n\n", pSCB->recvWindowNextSN);

	int capacity = MAX_BLOCK_SIZE * 4;
	// void * buffer = malloc(capacity);
	void * buffer = _alloca(capacity);
	if (buffer == NULL)
	{
		printf_s("Stack overflow in " __FUNCDNAME__  "\n");
		return;
	}

	// The 1st segment:
	pSocketItem->waitingRecvBuf = (BYTE *)buffer;
	// pSocketItem->peerCommitted = 0;	// See also FetchReceived()
	pSocketItem->bytesReceived = 0;
	pSocketItem->waitingRecvSize = MAX_BLOCK_SIZE / 2;

	int r = pSocketItem->FetchReceived();
	printf_s("Receive first SN = %u\n", pSCB->recvWindowFirstSN);
	printf_s("FetchReceived return %d, bytesReceived = %d\n", r, pSocketItem->bytesReceived);

	// the 2nd segment:
	pSocketItem->waitingRecvBuf = (BYTE *)buffer;
	// pSocketItem->peerCommitted = 0;	// See also FetchReceived()
	pSocketItem->bytesReceived = 0;
	pSocketItem->waitingRecvSize = MAX_BLOCK_SIZE / 4;

	r = pSocketItem->FetchReceived();
	printf_s("Receive first SN = %u\n", pSCB->recvWindowFirstSN);
	printf_s("FetchReceived return %d, bytesReceived = %d\n", r, pSocketItem->bytesReceived);

	// the 3rd segment: last one in one buffer block
	pSocketItem->waitingRecvBuf = (BYTE *)buffer;
	// pSocketItem->peerCommitted = 0;	// See also FetchReceived()
	pSocketItem->bytesReceived = 0;
	pSocketItem->waitingRecvSize = MAX_BLOCK_SIZE / 4;

	r = pSocketItem->FetchReceived();
	printf_s("Receive first SN = %u\n", pSCB->recvWindowFirstSN);
	printf_s("FetchReceived return %d, bytesReceived = %d\n", r, pSocketItem->bytesReceived);

	// the 4th: as the first segment
	pSocketItem->waitingRecvBuf = (BYTE *)buffer;
	// pSocketItem->peerCommitted = 0;	// See also FetchReceived()
	pSocketItem->bytesReceived = 0;
	pSocketItem->waitingRecvSize = MAX_BLOCK_SIZE / 2;

	r = pSocketItem->FetchReceived();
	printf_s("Receive first SN = %u\n", pSCB->recvWindowFirstSN);
	printf_s("FetchReceived return %d, bytesReceived = %d\n", r, pSocketItem->bytesReceived);

	// the 5th: cross one buffer block border
	pSocketItem->waitingRecvBuf = (BYTE *)buffer;
	// pSocketItem->peerCommitted = 0;	// See also FetchReceived()
	pSocketItem->bytesReceived = 0;
	pSocketItem->waitingRecvSize = MAX_BLOCK_SIZE;

	r = pSocketItem->FetchReceived();
	printf_s("Receive first SN = %u\n", pSCB->recvWindowFirstSN);
	printf_s("FetchReceived return %d, bytesReceived = %d\n", r, pSocketItem->bytesReceived);

	// the 6th: cross two buffer block border
	pSocketItem->waitingRecvBuf = (BYTE *)buffer;
	// pSocketItem->peerCommitted = 0;	// See also FetchReceived()
	pSocketItem->bytesReceived = 0;
	pSocketItem->waitingRecvSize = MAX_BLOCK_SIZE * 2;

	r = pSocketItem->FetchReceived();
	printf_s("Receive first SN = %u\n", pSCB->recvWindowFirstSN);
	printf_s("FetchReceived return %d, bytesReceived = %d\n", r, pSocketItem->bytesReceived);

	// To be tested in the real, blockable function:
	// the 7th: reach EoT prematurely
	// the 8th: buffer full
	// free(buffer);	// a heap has been corrupted!... well, InterlockedCompareExchangePointer...
}



#define RING_BUFFER_SIZE	(8 << 10)
#define testCompressedSize (128 << 10)
#define testInputSize (192 << 10)
#include <stdlib.h>
#include "../FSP_DLL/lz4.h"


inline U32 FUZ_rand(U32* src)
{
	rand_s(src);
	return *src;
}

#define FUZ_RAND15BITS  ((FUZ_rand(seed) >> 3) & 32767)
#define FUZ_RANDLENGTH  ( ((FUZ_rand(seed) >> 7) & 3) ? (FUZ_rand(seed) % 15) : (FUZ_rand(seed) % 510) + 15)
static void FUZ_fillCompressibleNoiseBuffer(void* buffer, size_t bufferSize, double proba, U32* seed)
{
	BYTE* const BBuffer = (BYTE*)buffer;
	size_t pos = 0;
	U32 const P32 = (U32)(32768 * proba);

	/* First Bytes */
	while (pos < 20)
		BBuffer[pos++] = (BYTE)(FUZ_rand(seed));

	while (pos < bufferSize) {
		/* Select : Literal (noise) or copy (within 64K) */
		if (FUZ_RAND15BITS < P32) {
			/* Copy (within 64K) */
			size_t const length = FUZ_RANDLENGTH + 4;
			size_t const d = min(pos+length, bufferSize);
			size_t match;
			size_t offset = FUZ_RAND15BITS + 1;
			while (offset > pos) offset >>= 1;
			match = pos - offset;
			while (pos < d) BBuffer[pos++] = BBuffer[match++];
		} else {
			/* Literal (noise) */
			size_t const length = FUZ_RANDLENGTH;
			size_t const d = min(pos+length, bufferSize);
			while (pos < d) BBuffer[pos++] = (BYTE)(FUZ_rand(seed) >> 5);
		}
	}
}



void FUZ_unitTests()
{
	typedef uint32_t U32;
	char ringBuffer[RING_BUFFER_SIZE];
	octet testInput[testInputSize];
	char testVerify[testInputSize];
	char testCompressed[testCompressedSize];

	LZ4_stream_t  streamingState;
	LZ4_streamDecode_t decodeState;

	const U32 maxMessageSizeLog = 12;
	const U32 maxMessageSizeMask = (1 << maxMessageSizeLog) - 1;
	U32 randValue = 0x3fdf;
	//
	FUZ_fillCompressibleNoiseBuffer(testInput, sizeof(testInput), 0.5, &randValue);
	//
	U32 messageSize = (randValue & maxMessageSizeMask) + 1;
	U32 iNext = 0;
	U32 rNext = 0;
	U32 dNext = 0;
	const U32 dBufferSize = RING_BUFFER_SIZE + maxMessageSizeMask;

	LZ4_resetStream(&streamingState);
	LZ4_setStreamDecode(&decodeState, NULL, 0);

	int result;
	while (iNext + messageSize < testCompressedSize)
	{
		printf_s("Message block size: %d\n", messageSize);

		memcpy(ringBuffer + rNext, testInput + iNext, messageSize);
		result = LZ4_compress_fast_continue(&streamingState, ringBuffer + rNext
			, testCompressed, messageSize, testCompressedSize - RING_BUFFER_SIZE, 1);

		printf_s("Compressed size: %d\n", result);
		// value of 'result' is the metadata that should be transfered
		result = LZ4_decompress_safe_continue(&decodeState, testCompressed, testVerify + dNext, result, messageSize);
		printf_s("Uncompressed size: %d\n\n", result);

		iNext += messageSize;
		rNext += messageSize;
		dNext += messageSize;

		rand_s(&randValue);
		messageSize = (randValue & maxMessageSizeMask) + 1;
		if (rNext + messageSize > RING_BUFFER_SIZE)
			rNext = 0;
		if (dNext + messageSize > dBufferSize)
			dNext = 0;
	}
}



#define SEGMENT_SIZE (128 << 10)	// As we already knew
#undef testInputSize
#undef testCompressedSize

// Test on-the-wire compression-decompression, covering branches
void UnitTestCompressAndDecode()
{
	CSocketItemDbg *pSocketItem = GetPreparedSocket();
	const int testInputSize = SEGMENT_SIZE * 4;
	const int testCompressedSize = LZ4_compressBound(testInputSize);
	char	*ringBuffer = (char *)malloc(testInputSize * 2);
	octet	*testInput = (octet *)malloc(testInputSize);
	char	*testVerify = (char *)malloc(testInputSize);
	char	*testCompressed = (char *)malloc(testCompressedSize);

	bool r = pSocketItem->AllocStreamState();
	assert(r);

	r = pSocketItem->AllocDecodeState();
	assert(r);

	U32 randValue = 0x3fdf;
	FUZ_fillCompressibleNoiseBuffer(testInput, testInputSize, 0.5, &randValue);

	// Compression
	// First default branch: just gobble in
	int k = testCompressedSize;
	int m = pSocketItem->Compress(testCompressed, k, testInput, SEGMENT_SIZE / 2);
	int m2 = m;
	int k2 = k;
	printf_s("Compression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", m, m2, k, k2);
	// Second branch: reach segment limit, force compression
	k = testCompressedSize - k2;
	m = pSocketItem->Compress(testCompressed + k2, k, testInput + m2, SEGMENT_SIZE);
	k2 += k;
	m2 += m;
	printf_s("Compression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", m, m2, k, k2);
	// Second branch, 2nd segment
	k = testCompressedSize - k2;
	m = pSocketItem->Compress(testCompressed + k2, k, testInput + m2, SEGMENT_SIZE);
	k2 += k;
	m2 += m;
	printf_s("Compression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", m, m2, k, k2);
	// Second branch, 3rd segment
	k = testCompressedSize - k2;
	m = pSocketItem->Compress(testCompressed + k2, k, testInput + m2, SEGMENT_SIZE);
	k2 += k;
	m2 += m;
	printf_s("Compression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", m, m2, k, k2);
	// Remaining test input, first default branch
	k = 1;
	m = pSocketItem->Compress(testCompressed + k2, k, testInput + m2, testInputSize - m2);
	k2 += k;
	m2 += m;
	printf_s("Compression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", m, m2, k, k2);
	// Third branch: end of transaction, force compression
	k = 1;
	m =	pSocketItem->Compress(testCompressed + k2, k, NULL, 0);
	assert(m == 0);
	k2 += k;
	printf_s("Compression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", m, m2, k, k2);
	// Fourth branch: the remains in the internal buffer
	k = 1;
	m = pSocketItem->Compress(testCompressed + k2, k, NULL, 0);
	assert(m == 0);
	k2 += k;
	printf_s("Compression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", m, m2, k, k2);
	// Fourth branch: safely called multiple times
	k = testCompressedSize - k2;
	m = pSocketItem->Compress(testCompressed + k2, k, NULL, 0);
	assert(m == 0);
	k2 += k;
	printf_s("Compression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", m, m2, k, k2);

	//Now k2 is the size of the compression result

	// Decompression
	// First branch: gobble in part of length field
	m = testInputSize;
	k = pSocketItem->Decompress(testVerify, m, testCompressed, 1);
	m2 = m;
	int n = k;
	assert(k == 1);
	printf_s("Decompression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", k, n, m, m2);

	// Second branch: gobble in remaining length field AND some data
	m = testInputSize - m2;
	k = pSocketItem->Decompress(testVerify + m2, m, testCompressed + 1, SEGMENT_SIZE / 8 - 1);
	m2 += m;
	n += k;
	assert(k == SEGMENT_SIZE / 8 - 1 && n == SEGMENT_SIZE / 8);
	printf_s("Decompression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", k, n, m, m2);
	// Third branch: gobble in remaining data
	m = testInputSize - m2;
	k = pSocketItem->Decompress(testVerify + m2, m, testCompressed + SEGMENT_SIZE / 8,  k2 - SEGMENT_SIZE / 8);
	m2 += m;
	n += k;
	printf_s("Decompression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", k, n, m, m2);
	// Not all data may be gobbled
	while((k2 - n) > 0)
	{
		m = SEGMENT_SIZE / 4 * 3;
		k = pSocketItem->Decompress(testVerify + m2, m, testCompressed + n,  k2 - n);
		m2 += m;
		n += k;
		printf_s("Decompression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", k, n, m, m2);
	}
	// Fourth branch: copy out some decompression data (1 octet)
	m = 1;
	k = pSocketItem->Decompress(testVerify + m2, m, NULL, 0);
	m2 += m;
	n += k;
	printf_s("Decompression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", k, n, m, m2);
	// Fourth branch, 2nd: copy out the remains in the internal buffer
	m = testInputSize - m2;
	k = pSocketItem->Decompress(testVerify + m2, m, NULL, 0);
	m2 += m;
	n += k;
	printf_s("Decompression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", k, n, m, m2);
	// Fifth branch, both input and internal buffer are empty
	m = 1;	// it should not make it overflow
	k = pSocketItem->Decompress(testVerify + m2, m, NULL, 0);
	m2 += m;
	n += k;
	printf_s("Decompression:\t%d bytes gobbled(total %d)\n\t\t%d bytes output(total %d).\n", k, n, m, m2);
	// Sixth branch: illegal input
	m = testInputSize - m2;
	k = pSocketItem->Decompress(testVerify + m2, m, NULL, 0);
	printf_s("At last, decompression return %d\n", k);
}



int _tmain(int argc, _TCHAR* argv[])
{
	//FUZ_unitTests();
	UnitTestCompressAndDecode();

	//UnitTestCheckedRevertCommit();

	//UnitTestBufferData();

	LogicTestPackedSend();

	//UnitTestPrepareToSend();

	//UnitTestFetchReceived();

	return 0;
}

