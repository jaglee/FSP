/*
 * FSP lower-layer service program, the entry point, the top-level control,
 * AND the security related issues.
 * Platform-dependent / IPC-mechanism-dependent
 * Garbage Collection is treated as a security-related issue.
 * The FSP Finite State Machine is split across command.cpp, remote.cpp and timers.cpp
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


// The singleton instance of the connect request queue
ConnectRequestQueue ConnectRequestQueue::requests;

// The singleton instance of the lower service interface 
CLowerInterface	CLowerInterface::Singleton;

extern void LOCALAPI ProcessCommand(void *buffer);

#if defined(__WINDOWS__)

// access control is centralized managed in the 'main' source file
# include <Accctrl.h>
# include <Aclapi.h>

// get the security attribute of the service, assigned to the mailslot - shall be everyone's free access
static void GetServiceSA(PSECURITY_ATTRIBUTES);

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
	if(!CLowerInterface::Singleton.Initialize())
	{
		printf("In main cannot access lower interface, aborted.\n"); 
		goto l_bailout;
	}

	// continue on main thread (thread 1):
	// Remark
	//	Terminate only when the mailslot is unreadable due to some panic
	try
	{
		octet buffer[MAX_CTRLBUF_LEN];
		DWORD nBytesRead;
		while(ReadFile(md, buffer, MAX_CTRLBUF_LEN, & nBytesRead, NULL))
		{
#if defined(TRACE) && (TRACE & TRACE_ULACALL)
			printf_s("\n%d octets read from the mailslot.", nBytesRead);
#endif
			if(nBytesRead < sizeof(struct CommandToLLS))
			{
#if defined(TRACE) && (TRACE & TRACE_ULACALL)
				printf_s(" Size of the message is too small.\n");
#endif
				continue;
			}
			ProcessCommand(buffer);
			// There used to be "hard-coded: (ushort)(-1) mean exit". But it allowed DoS attack
		}
#ifndef NDEBUG
		// TODO: UNRESOLVED! Crash Recovery? if ReadFile fails, it is a crash
		printf("Fatal! Read mailslot error, command channel broken\n");
#endif
	}
	catch(...)
	{
		BREAK_ON_DEBUG();
		CLowerInterface::Singleton.Destroy();
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

#elif defined(__linux__) || defined(__CYGWIN__)

int main(int argc, char * argv[])
{
	struct mq_attr mqa;
    mqd_t mqdes;

	mqa.mq_flags = 0;       /* Flags (ignored for mq_open()) */
	mqa.mq_maxmsg = 5;      /* Max. # of messages on queue */
	mqa.mq_msgsize = MAX_CTRLBUF_LEN;
	mqa.mq_curmsgs = 0;     /* # of messages currently in queue */

	mqdes = mq_open(SERVICE_MAILSLOT_NAME, O_RDONLY | O_CREAT, 0777, &mqa);

    if (mqdes == (mqd_t) -1)
	{
		printf("To read %s:\n", SERVICE_MAILSLOT_NAME);
		perror("cannot create open the message queue");
		exit(-1);
	}

	// also create the receiver
	if(!CLowerInterface::Singleton.Initialize())
	{
		printf("In main cannot access lower interface, aborted.\n"); 
		goto l_bailout;
	}

	// continue on main thread (thread 1):
	try
	{
		char buffer[MAX_CTRLBUF_LEN];
		unsigned int msg_prio;;
		ssize_t nBytesRead;
		while((nBytesRead = mq_receive(mqdes, buffer, MAX_CTRLBUF_LEN, &msg_prio)) > 0)
		{
#if defined(TRACE) && (TRACE & TRACE_ULACALL)
			printf_s("\n%d octets read from the mailslot.", (int)nBytesRead);
#endif
			if(nBytesRead < (ssize_t)sizeof(struct CommandToLLS))
			{
#if defined(TRACE) && (TRACE & TRACE_ULACALL)
				printf_s(" Size of the message is too small.\n");
#endif
				continue;
			}
			ProcessCommand(buffer);
			// There used to be "hard-coded: (ushort)(-1) mean exit". But it allowed DoS attack
		}
#ifndef NDEBUG
		// TODO: UNRESOLVED! Crash Recovery? if ReadFile fails, it is a crash
		printf("Fatal! Read mailslot error, command channel broken\n");
#endif
	}
	catch(...)
	{
		BREAK_ON_DEBUG();
		CLowerInterface::Singleton.Destroy();
	}

l_bailout:
	mq_unlink(SERVICE_MAILSLOT_NAME);
	return 0;
}

#endif

