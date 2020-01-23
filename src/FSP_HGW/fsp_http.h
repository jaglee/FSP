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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>


#if defined(_WIN32)

# include <io.h>
# include <share.h>

typedef int socklen_t;

# pragma comment(lib, "Ws2_32.lib")

#elif defined(__linux__) || defined(__CYGWIN__)

# include <pthread.h>
# include <strings.h>
# include <sys/socket.h>
# include <sys/wait.h>
# include <unistd.h>
# define closesocket    close
# define _strcmpi   strcasecmp

static inline void Sleep(int32_t millis)
{
    struct timespec tv;
    tv.tv_sec = millis / 1000;
    tv.tv_nsec = (millis % 1000) * 1000000;
    nanosleep(&tv, NULL);
}

#endif

#include "../FSP_API.h"
#include "../Crypto/CHAKA.h"

#include "defs.h"

struct LineBuffer
{
	int		firstOffset;
	int		lastOffset;
	char	buf[BUFFER_POOL_SIZE];
};


// Definition of pointer to Flexible Session Associated Data
// We make sure it may be safely casted to LineBuffer *
typedef struct AssociatedData: LineBuffer
{
	SCHAKAPublicInfo chakaPubInfo;
	octet sessionClientIdString[MAX_PATH];
	octet salt[CRYPTO_SALT_LENGTH];
	octet passwordHash[CRYPTO_NACL_HASHBYTES];
	octet bufSharedKey[CRYPTO_NACL_KEYBYTES];
} *PFSAData;


// Server side forward declarations
int	FSPAPI onMultiplying(FSPHANDLE, PFSP_SINKINF, PFSP_IN6_ADDR);
void ReportToRemoteClient(PRequestPoolItem, ERepCode);


// Given
//	const *		the error message meant to be put on system console (and should be logged)
// Do
//	Exit the program abruptly for some fatal reason
void	Abort(const char*);

// Given
//	FSPHANDLE		The handle of the FSP connection that was made towards the browser
//					that supports HTTP over FSP, or the tunnel service client
//	const char *	path of the executable
//	const char *	invoke HTTP method of the executable. 'GET' or 'POST' only for this version
//	const char *	the query string in the original URL that was meant to pass to the executable
// Do
//	Execute the CGI executable that subjected to *FCGI* management
void	execute_cgi(FSPHANDLE, const char*, const char*, const char*);

// Given
//	FSPHANDLE	The handle of the FSP connection that was made towards the browser
//	char *		The buffer to hold the request line
//	int			The capacity of the buffer which should be more than 80, less than 32767
// Return
//	Non-negative:	number of octets read,
//	Negative:		the error number
// Remark
//	Request byte stream is further buffered internally
int		ReadLine(FSPHANDLE, char*, int);

// Given
//	FSPHANDLE		The handle of the FSP connection that was made towards the browser
//	const char *	the name of the file whose content is meant to be sent to the browser
// Do
//	Read the content of file and send the binary stream to the remote end
// Remark
//	For this version assume only the html content type is supported
void	SendRegFile(FSPHANDLE, const char*);


// UNRESOLVED! report error message 'cannot execute'
static inline void    cannot_execute(FSPHANDLE client) { return; }


// UNRESOLVED! report error message 'bad request'
static inline void    bad_request(FSPHANDLE client) { return; }
