/*
 * DLL to service FSP upper layer application
 * Session control functions: Multiplication/Commitment/Resumption
 * Milk-transport is only implented on multiplicated secondary connection
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


/*
SIO_ENABLE_CIRCULAR_QUEUEING
Indicates to the underlying message-oriented service provider that
a newly arrived message should never be dropped because of a buffer queue overflow.
Instead, the oldest message in the queue should be eliminated in order to accommodate the newly arrived message.
No input and output buffers are required.
Note that this IOCTL is only valid for sockets associated with unreliable, message-oriented protocols.
The WSAENOPROTOOPT error code is indicated for service providers that do not support this IOCTL.
*/
/**
6.3  ConnectMU
(1)	�ϲ�Ӧ�õ���DLL��ConnectMU������ָ��ϣ�����Ƶ�FSP���Ӿ��Զ�����ӳɹ�������ȷʧ�ܣ�ʱ�Ļص�������Milk-transport��꣬�Լ���ѡ�ı��ط������ݿ飻
(2)	DLL��Э��Ҫ��������Զ�˷������Ӹ��Ʊ��ģ������ñ�����Ϊ���Ͷ���ͷ���������б������ݣ������WriteTo������
(3)	DLL��LLS���ݲ������������ݷ�ʽͬConnect2��
(4)	LLS�����µı���Session ID������Э��涨��������λ�ڷ��Ͷ���ͷ�ı��ģ�
(5)	LLS�ڼ����յ�������Ӧ����ICC����󣬽������ձ���������ն��У�Ȼ�󴥷�ͬ���¼���
(6)	DLL���¼��ȴ������̻߳�ȡ���ؽ���������ϲ�Ӧ���ṩ�Ļص�����������ϲ�Ӧ��ȷ�Ͻ������ӣ���������Ҫ�������շ����ݻ�������������DLLʹ���ӽ���ACTIVE״̬����������б������ݣ������RecvInline����������ϲ�Ӧ����ʾܾ����ӣ���DLLͨ��Reject�����֪LLS��ӦRESET���ͷ���Դ��
(7)	���ܷ������쳣��
i.	�ϲ�Ӧ�ô��ݵķ��ͻ�������/����ջ�������С����ʵ�����ƣ�
ii.	���������Ӳ����ã�
iii.	�޿��еı���Session ID��
iv.	�޷������첽ͨѶ���õ��̳߳أ�
v.	Զ�˾ܾ����Ӹ��ƣ�Զ�����޿��е�Session ID��ԭ�򣬻ظ����оܾ����Reset���ģ���
vi.	��ʱ��
vii.	��������ʱ����
**/
//[API: Multiply]
//	NON_EXISTENT-->CLONING-->[Send MULTIPLY]{enable retry}
// UNRESOLVED! ALLOCATED NEW SESSION ID in LLS?
// Given
//	FSPHANDLE		the handle of the parent FSP socket to be multiplied
//	PFSP_Context	the pointer to the parameter structure of the socket to create by multiplication
// Return
//	the handle of the new created socket
//	or NULL if there is some immediate error, more information may be got from the flags set in the context parameter
// Remark
//	Even the function return no immediate error, the callback function may be called with a NULL FSPHANDLE
//	which indicate some error has happened. In that case ULA might make further investigation by calling GetLastFSPError()
DllExport
FSPHANDLE FSPAPI ConnectMU(FSPHANDLE hFSP, PFSP_Context psp1)
{
	TRACE_HERE("called");
	if(hFSP == NULL)
	{
		psp1->u.flags = EBADF;
		return NULL;
	}

	TRACE_HERE("called");

	// TODO: SHOULD inherit the latest effective near address
	IN6_ADDR addrAny = IN6ADDR_ANY_INIT;
	psp1->u.st.passive = 0;	// override what is provided by ULA
	CommandNewSession objCommand;
	CSocketItemDl * socketItem = CSocketItemDl::CreateControlBlock((PFSP_IN6_ADDR) & addrAny, psp1, objCommand);
	if(socketItem == NULL)
	{
		psp1->u.flags = EBADF;	// E_HANDLE;
		return NULL;
	}
	// TODO: SHOULD constuct the MULTIPLY command packet

	// TODO: SHOULD install a new, derived session key!
	// socketItem->pControlBlock->connectParams = ...;

	return socketItem->CallCreate(objCommand, SynConnection);
}



//{ACTIVE, COMMITTING, PEER_COMMIT, COMMITTING2, COMMITTED, CLOSABLE}
//	|-->/MULTIPLY/-->[API{Callback}]
//	|-->[{Return Accept}]-->{new context}ACTIVE
//		-->[Send PERSIST]{start keep-alive}
//	|-->[{Return Commit}]-->{new context}COMMITTING
//		-->[Send COMMIT]{enable retry}
//	|-->[{Return}:Reject]-->[Send RESET] {abort creating new context}
bool LOCALAPI CSocketItemDl::ToWelcomeMultiply(BackLogItem & backLog)
{
	// Multiply: but the upper layer application may still throttle it...fpRequested CANNOT read or write anything!
	PFSP_IN6_ADDR remoteAddr = (PFSP_IN6_ADDR) & pControlBlock->peerAddr.ipFSP.allowedPrefixes[MAX_PHY_INTERFACES-1];

	int r;
	if( fpRequested == NULL	// This is NOT the same policy as ToWelcomeConnect
	|| (r = fpRequested(this, & backLog.acceptAddr, remoteAddr)) < 0 )
	{
		// UNRESOLVED! report that the upper layer application reject it?
		return false;
	}

	if(r == 0 && pControlBlock->hasPendingKey == 0)
		SetState(ESTABLISHED);
	else
		SetState(COMMITTING);

	return true;
}


//[{return}Accept]
//	{CLOSABLE, CLOSED}-->[Rcv.RESUME]-->[API{callback}]-->/return Accept/
//		-->ACTIVE-->[Send PERSIST]{restart keep-alive}
//[{return}Commit]
//	CLOSABLE-->[Rcv.RESUME]-->[API{callback}]
//		-->/return Commit/-->COMMITTING-->[Send COMMIT]{enable retry}
//	CLOSED-->[Rcv.RESUME]-->[API{callback}]
//		-->/return Commit/-->COMMITTING-->[Send COMMIT]{enable retry}
//[{return}Reject]
//	CLOSABLE-->[Rcv.RESUME]-->[API{callback}]-->/return Reject/
//		-->[Send RESET]-->NON_EXISTENT
//	CLOSED-->[Rcv.RESUME]-->[API{callback}]-->/return Reject/
//		-->[Send RESET]-->NON_EXISTENT
// Auxiliary function that is called when an existing closed connection context is hit in the cache
void CSocketItemDl::HitResumableDisconnectedSessionCache()
{
	if(! WaitUseMutex())
	{
		TRACE_HERE("deadlock encountered!?");
		return;
	}
	//...
	SetMutexFree();
}
