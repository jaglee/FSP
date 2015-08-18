/*
 * FSP lower-layer service program, the entry point, the top-level control control,
 * AND the security related issues.
 * Platform-dependent / IPC-machanism-dependent
 * Garbage Collection is treated as a security-related issue.
 * handling the UDP/IPv4 (IPv6 in the long run) addresses of the near-end
 * including processing event of IP address change that are key to mobility support
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

// The FSP Finite State Machine is splitted across command.cpp, remote.cpp and timers.cpp

#include "fsp_srv.h"

// access control is centralized managed in the 'main' source file
#include <Accctrl.h>
#include <Aclapi.h>

// get the security attribute of the service, assigned to the mailslot - shall be everyone's free access
static void GetServiceSA(PSECURITY_ATTRIBUTES);

static void LOCALAPI ProcessCommand(HANDLE);

extern "C"
int main(int argc, char * argv[])
{
	SECURITY_ATTRIBUTES attrSecurity;
	GetServiceSA(& attrSecurity);

	HANDLE md = CreateMailslot(SERVICE_MAILSLOT_NAME
		, MAX_CTRLBUF_LEN
		, MAILSLOT_WAIT_FOREVER
		, & attrSecurity);
	if(md == INVALID_HANDLE_VALUE)
	{
		printf("Panic!Cannot create the mailslot to accept service request.\n");
		return -1;
	}

	// also create the receiver
	try
	{
		new CLowerInterface();
	}
	catch(HRESULT x)
	{
		// TODO: UNRESOLVED!handle the exception?!
		printf("In main: exception number 0x%X, cannot access lower interface, aborted.\n", x); 
		goto l_bailout;
	}

	try
	{
		new TimerWheel();
	}
	catch(HRESULT x)
	{
		printf("In main: exception number 0x%X, internal panic!Cannot start the timer\n", x); 
		goto l_bailout;
	}

	// continue on main thread (thread 1):
	try
	{
		ProcessCommand(md);
	}
	catch(...)
	{
		delete TimerWheel::Singleton();
		delete CLowerInterface::Singleton();
		TRACE_HERE("Exception caught on processing upper layer command.");
	}

l_bailout:
	CloseHandle(md);
	return 0;
}



// a security attribute depends on a security descriptor
// while a security descriptor depends on an ACL
// while an ACL contains at least one explicit access entry (ACL entry) [if it is NULL, by default everyone access]
// while an explicit access entry requires a SID
static void GetServiceSA(PSECURITY_ATTRIBUTES pSA)
{
    PSID pEveryoneSID = NULL;
    PACL pACL = NULL;
    EXPLICIT_ACCESS ea;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	static SECURITY_DESCRIPTOR sd;	// as it is referenced by pSA

    // Create a well-known SID for the Everyone group.
    if(!AllocateAndInitializeSid(&SIDAuthWorld, 1,
                     SECURITY_WORLD_RID,	// dwSubAuthority0
                     0, 0, 0, 0, 0, 0, 0, // dwSubAuthority 1~7
                     & pEveryoneSID))
    {
#ifndef NDEBUG
        printf("AllocateAndInitializeSid Error %u\n", GetLastError());
#endif
        goto Cleanup;
    }

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow Everyone read access to the key.
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = GENERIC_ALL;	// SPECIFIC_RIGHTS_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance= NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName  = (LPTSTR) pEveryoneSID;

    // Create a new ACL that contains the new ACEs.
    if (SetEntriesInAcl(1, & ea, NULL, &pACL) != ERROR_SUCCESS) 
    {
#ifndef NDEBUG
        printf("SetEntriesInAcl Error %u\n", GetLastError());
#endif
        goto Cleanup;
    }
 
    if (!InitializeSecurityDescriptor(& sd, SECURITY_DESCRIPTOR_REVISION)) 
    {  
#ifndef NDEBUG
        printf("InitializeSecurityDescriptor Error %u\n", GetLastError());
#endif
        goto Cleanup; 
    } 
 
    // Add the ACL to the security descriptor. 
    if (!SetSecurityDescriptorDacl(& sd, 
            TRUE,     // bDaclPresent flag   
            pACL, 
            FALSE))   // not a default DACL 
    {  
        printf("SetSecurityDescriptorDacl Error %u\n", GetLastError());
        goto Cleanup; 
    } 

    // Initialize a security attributes structure.
	
    pSA->nLength = sizeof (SECURITY_ATTRIBUTES);
    pSA->lpSecurityDescriptor = & sd;
    pSA->bInheritHandle = FALSE;

Cleanup:
	;	// do not free SID or ACL, until the process terminated(?) 
    //if (pEveryoneSID) 
    //    FreeSid(pEveryoneSID);
	// if(pACL)
	//	  LocalFree(pACL);
}


// Get upper layer application's commands and process them
// Given
//	_In_ md the handle of the mailslot receiving ULA commands
// Return
//	Nothing
// Remark
//	Terminate only when the mailslot is unreadable due to some panic
static void LOCALAPI ProcessCommand(HANDLE md)
{
	BYTE buffer[MAX_CTRLBUF_LEN];
	DWORD nBytesRead;
	CommandToLLS *pCmd = (CommandToLLS *) buffer;
	// TODO: UNRESOLVED!there should be performance profiling variables to record how many commands have been processed?
    static int n = 0;
	CSocketItemEx *pSocket;
	// TRACE_HERE("called");
	while(ReadFile(md, buffer, MAX_CTRLBUF_LEN, & nBytesRead, NULL))
	{
		if(nBytesRead < sizeof(struct CommandToLLS))
			continue;
//#ifdef TRACE
//		printf("%d bytes read, command operation code = %d\n",  nBytesRead, ((struct CommandToLLS *) buffer)->opCode);
//#endif
		//
		switch(pCmd->opCode)
		{
		case FSP_Listen:		// register a passive socket
			printf_s("Requested to listen on local fiber#%d, assigned event trigger is %s\n"
				, pCmd->fiberID
				, ((CommandNewSession *)pCmd)->szEventName);
			Listen(CommandNewSessionSrv(pCmd));
			break;
		case InitConnection:	// register an initiative socket			
			Connect(CommandNewSessionSrv(pCmd));
			break;
		case SynConnection:
			SyncSession(CommandNewSessionSrv(pCmd));
			break;
		default:
			pSocket = (CSocketItemEx *)(*CLowerInterface::Singleton())[pCmd->fiberID];
			if(pSocket == NULL || !pSocket->IsInUse())
			{
#ifdef TRACE
				printf_s("Erratic!%s (code = %d) called for invalid local fiber#%u\n"
					, opCodeStrings[pCmd->opCode]
					, pCmd->opCode
					, pCmd->fiberID);
#endif
				break;
			}
			//
			switch(pCmd->opCode)
			{
			case FSP_Reject:
				pSocket->Disconnect();
				break;
			case FSP_Recycle:
				pSocket->CloseSocket();
				break;
			case FSP_Start:
				pSocket->Start();
				break;
			case FSP_Send:			// send a packet/group of packets
				pSocket->ScheduleEmitQ();
				break;
			case FSP_Urge:
				pSocket->UrgeCommit();
				break;
			case FSP_Shutdown:
				pSocket->Shutdown();
				break;
			case FSP_InstallKey:
				pSocket->InstallSessionKey();
				break;
			default:
	#ifndef NDEUBG
				printf("Internal error: undefined upper layer application command code %d\n", pCmd->opCode);
	#endif
				break;
			}
		}
		// hard-coded: (ushort)(-1) mean exit
		if(buffer[0] == 0xFF || buffer[1] == 0xFF)
			break;
		//
		n++;
	}
#ifndef NDEBUG
	// TODO: UNRESOLVED!Crash Recovery? if ReadFile fails, it is a crash
	printf("Fatal!Read mailslot error, command channel broken\n");
#endif
}
