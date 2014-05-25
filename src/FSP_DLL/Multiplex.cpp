/*
 * DLL to service FSP upper layer application
 * Session control functions: Multiplication/Adjournment/Resumption
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
(1)	上层应用调用DLL中ConnectMU函数，指定希望复制的FSP连接句柄远、连接成功（或明确失败）时的回调函数、Milk-transport旗标，以及可选的背载发送数据块；
(2)	DLL按协议要求，生成向远端发送连接复制报文，并将该报文置为发送队列头（其中如有背载数据，则参照WriteTo处理）；
(3)	DLL向LLS传递参数，参数传递方式同Connect2；
(4)	LLS分配新的本端Session ID，并按协议规定动作发送位于发送队列头的报文；
(5)	LLS在检查接收到的连接应答报文ICC无误后，将所接收报文置入接收队列，然后触发同步事件；
(6)	DLL的事件等待工作线程获取返回结果，调用上层应用提供的回调函数，如果上层应用确认接受连接（并根据需要继续做收发数据或其他处理），则DLL使连接进入ACTIVE状态（其中如果有背载数据，则参照RecvInline处理）；如果上层应用因故拒绝连接，则DLL通过Reject命令告知LLS回应RESET并释放资源。
(7)	可能发生的异常：
i.	上层应用传递的发送缓冲区和/或接收缓冲区大小超过实现限制；
ii.	被复制连接不可用；
iii.	无空闲的本地Session ID；
iv.	无法创建异步通讯所用的线程池；
v.	远端拒绝连接复制（远端因无空闲的Session ID等原因，回复带有拒绝码的Reset报文）；
vi.	超时；
vii.	其他运行时错误。
**/
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
	// TODO: SHOULD derive ephemeral seesion key from the parent session at first. See also CopyKey()
	// TODO: SHOULD constuct the MULTIPLY command packet
	return socketItem->CallCreate(objCommand, SynConnection);
}


//[{return}Accept{new context}]
//{ACTIVE on multiply request}-->/[API{callback}]/
//    -->{start keep-alive}ACTIVE
//[{return}Commit{new context}] 
//{ACTIVE on multiply request}-->/API{callback}/
//      -->{new context}PAUSING-->[Snd ADJOURN {in the new context}]
//[{return}Reject]
//{ACTIVE on multiply request}-->/API{callback}/
//      -->[Snd RESET]-->{abort creating new context, no state transition}
//| --[Rcv MULTIPLY]-->[API{ Callback }]
//| -->[{Return Commit}]-->{new context}PAUSING
//-->[Snd ADJOURN{ enable retry, in the new context }]
//| -->[{Return Accept}]-->{new context}ACTIVE
//-->[Snd PERSIST{ start keep - alive, in the new context }]
// 情形1：(PERSIST, ICC, 流控参数, 半连接参数，载荷)
// 情形2：(ADJOURN, ICC, 流控参数, SNACK, 载荷)
// 情形3：RESET...
// UNRESOLVED! ALLOCATED NEW SESSION ID in LLS
bool LOCALAPI CSocketItemDl::ToWelcomeMultiply(BackLogItem & backLog)
{
	if(CopyKey(backLog.idParent) < 0)
	{
		TRACE_HERE("Process listening backlog: : illegal multiplication, silently discard it");
		return false;
	}

	// Multiply: but the upper layer application may still throttle it...fpRequested CANNOT read or write anything!
	PFSP_IN6_ADDR remoteAddr = (PFSP_IN6_ADDR) & pControlBlock->peerAddr.ipFSP.allowedPrefixes[MAX_PHY_INTERFACES-1];
	int r;
	if( fpRequested == NULL	// This is NOT the same policy as ToWelcomeConnect
	|| (r = fpRequested(this, & backLog.acceptAddr, remoteAddr)) < 0 )
	{
		// UNRESOLVED! report that the upper layer application reject it?
		return false;
	}

	ControlBlock::PFSP_SocketBuf skb = pControlBlock->HeadSend();
	if(r > 0)
	{
		// TODO: force to slide the send window, and merge with the latest data packet
		// TODO: check 'QUASI_ACTIVE' state in the sending function
		skb->opCode = ADJOURN;
		SetState(PAUSING);
	}
	else
	{
		FSP_AckConnectRequest & welcome = *(FSP_AckConnectRequest *)GetSendPtr(skb);
		FSP_ConnectParam & varParams = welcome.params;
		// TODO: handle of milky-payload; multihome/mobility support is always handled by LLS
		varParams.delayLimit = 0;
		varParams.initialSN = pControlBlock->u.connectParams.initialSN;
		varParams.listenerID = pControlBlock->idParent;
		varParams.hs.Set<CONNECT_PARAM>(sizeof(FSP_NormalPacketHeader) + sizeof(FSP_AckConnectKey));
		welcome.hsKey.Set<EPHEMERAL_KEY>(sizeof(FSP_NormalPacketHeader));
		welcome.hs.Set<PERSIST>(sizeof(welcome));
		//
		skb->opCode = PERSIST;	// unlike in CHALLENGING state
		skb->len = sizeof(welcome);
		//
		SetState(ESTABLISHED);
	}
	// the integrityCode is to be automatically set by LLS
	skb->SetFlag<IS_COMPLETED>();

	return true;
}


// Auxiliary function that is called
// when an existing close/closable connection context is hit in the cache
//[{return}Accept]
//CLOSABLE-->[Rcv RESTORE]-->/[API{callback}]/
//    -->{start keep-alive}ACTIVE
//CLOSED-->[Rcv RESTORE]-->/[API{callback}]/
//    -->{start keep-alive}ACTIVE
//[{return}Commit]
//CLOSABLE-->[Rcv RESTORE]-->[API{callback}]-->PAUSING
//CLOSED-->[Rcv RESTORE]-->[API{callback}]-->PAUSING
//[{return}Reject]
//CLOSABLE{on resumption request}-->/API{callback}/
//      -->[Snd RESET]-->NON_EXISTENT{to discard the contxt}
//CLOSED{on resurrect request}-->/API{callback}/
//      -->[Snd RESET]-->NON_EXISTENT{to discard the context}
void CSocketItemDl::HitResumableDisconnectedSessionCache()
{
	SetMutexFree();
}
