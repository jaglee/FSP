/*
 * Provide stubs to some interesting crypto functions in RTL
 *
    Copyright (c) 2017, Jason Gao
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

#ifdef _MSC_VER
#define FSPAPI __stdcall
#define DllSpec __declspec(dllexport)
#else
#define FSPAPI
#define DllSpec
#endif

typedef unsigned char octet;	// keep sync with CrytoStub.h

// OS-dependent crypto service
#define WIN32_LEAN_AND_MEAN
#define STRICT
#include <Windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

#include <malloc.h>
#include <stdio.h>

DllSpec
void randombytes(void *buf, size_t len)
{
	static HCRYPTPROV   hCryptProv;
	if(! hCryptProv
	&& ! CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT + CRYPT_SILENT))
	{
#ifdef _DEBUG
		printf_s("CryptAcquireContext() return %d\n", GetLastError());
		DebugBreak();
#endif
		return;
	}
	CryptGenRandom(hCryptProv, (DWORD)len, (BYTE *)buf);
}



// Assume the wide string utf16data is NUL-terminated
DllSpec
int WideStringToUTF8(octet buffer[], int capacity, LPCWCH utf16data)
{
	DWORD kFlags = WC_ERR_INVALID_CHARS;

	// Prevent buffer overflow issue for sake of security
    int utf8Length = WideCharToMultiByte(
        CP_UTF8,            // convert to UTF-8
        kFlags,             // conversion flags
        utf16data,			// source UTF-16 string
        -1,					// assume the input wide-char string is NUL-terminated
        NULL,				// unused - no conversion required in this step
        0,                  // request size of destination buffer, in octets
        NULL, NULL
    );

	if(utf8Length > capacity || utf8Length <= 0)
		return -1;

	// Do the actual conversion from UTF-16 to UTF-8
	return WideCharToMultiByte(
        CP_UTF8,            // convert to UTF-8
        kFlags,             // conversion flags
        utf16data,			// source UTF-16 string
        -1,					// assume the input wide-char string is NUL-terminated
        (LPSTR)buffer,		// pointer to destination buffer
        utf8Length,         // size of destination buffer, in octets
        NULL, NULL
    );
}



// It is asymmetric with WideStringToUTF8, in the sense that the output is NOT guaranteed NUL-terminated
// Precheck buffer overflow issue for sake of security
DllSpec
int UTF8ToWideChars(wchar_t buffer[], int capacity, LPCSTR utf8data, int utf8Length)
{
    DWORD kFlags = MB_ERR_INVALID_CHARS;

	// Prevent buffer overflow issue for sake of security
    int utf16Length = MultiByteToWideChar(
        CP_UTF8,		// source string is in UTF-8
        kFlags,			// conversion flags
        utf8data,		// source UTF-8 string pointer
        utf8Length,		// length of the source UTF-8 string, in octets
        NULL,			// unused - no conversion done in this step
        0				// request size of destination buffer, in wchar_ts
    );
	//
    if (utf16Length <= 0 || utf16Length > capacity)
		return -1;

    // Do the actual conversion from UTF-8 to UTF-16
   return MultiByteToWideChar(
        CP_UTF8,		// source string is in UTF-8
        kFlags,			// conversion flags
        utf8data,		// source UTF-8 string pointer
        utf8Length,		// length of source UTF-8 string, in chars
        buffer,			// pointer to destination buffer
	   utf16Length		// size of destination buffer, in wchar_ts           
    );
}



/**
	For the code pages listed below, dwFlags must be set to 0. Otherwise, the function fails with ERROR_INVALID_FLAGS.
	50220 iso-2022-jp
	50221 csISO2022JP
	50222 iso-2022-jp
	50225 iso-2022-kr
	50227 Simplified Chinese, ISO 1022
	50229 ISO 2022 Traditional Chinese
	57002 through 57011 x-iscii-.. ISCII
	65000 (UTF-7)
	42 (Symbol)
	Note  For UTF-8 or code page 54936 (GB18030, starting with Windows Vista), dwFlags must be set to either 0
	or MB_ERR_INVALID_CHARS. Otherwise, the function fails with ERROR_INVALID_FLAGS.
 */
DllSpec
int LocalMBCSToUTF8(octet buffer[], int capacity, LPCSTR strData)
{
	UINT codePage = CP_ACP;
	int charLength;
	int ret = -1;
	wchar_t * utf16data;

	// Prevent buffer overflow issue for sake of security
	int utf16Length = MultiByteToWideChar(
		codePage,
		0,				// conversion flags
		strData,		// source UTF-8 string pointer
		-1,				// NUL-terminated
		NULL,			// unused - no conversion done in this step
		0				// request size of destination buffer, in wchar_ts
	);
	//
	if (utf16Length <= 0)
	{
		ret = -(int)GetLastError();
		return ret;	//  ERROR_NO_UNICODE_TRANSLATION     1113L
	}

	utf16data = (wchar_t *)LocalAlloc(LPTR, sizeof(wchar_t *) * utf16Length);
	if (utf16data == NULL)
		return ret;

	// Do the actual conversion from UTF-8 to UTF-16
	if (MultiByteToWideChar(
		codePage,
		0,				// conversion flags
		strData,		// source UTF-8 string pointer
		-1,				// NUL-terminated
		utf16data,		// pointer to destination buffer
		utf16Length		// size of destination buffer, in wchar_ts           
	) <= 0)
	{
		goto l_bailout;
	}

	// convert back to MBCS again. this time it is in UTF8
	// Prevent buffer overflow issue for sake of security
	charLength = WideCharToMultiByte(
		CP_UTF8,			// convert to UTF8
		0,					// conversion flags
		utf16data,			// source UTF-16 string
		utf16Length,		// length of the source string, in wchar_ts
		NULL,				// unused - no conversion required in this step
		0,                  // request size of destination buffer, in octets
		NULL, NULL
	);

	if (charLength > capacity)
		goto l_bailout;

	if (charLength <= 0)
	{
		ret = -(int)GetLastError();
		goto l_bailout;
	}

	// Do the actual conversion from UTF-16 to UTF8
	ret = WideCharToMultiByte(
		CP_UTF8,			// convert to UTF8
		0,					// conversion flags
		utf16data,			// source UTF-16 string
		utf16Length,		// length of the source string, in wchar_ts
		(LPSTR)buffer,		// pointer to destination buffer
		charLength,			// size of destination buffer, in octets
		NULL, NULL
	);

l_bailout:
	LocalFree((HLOCAL)utf16data);
	return ret;
}




// Precheck buffer overflow issue for sake of security
DllSpec
int UTF8ToLocalMBCS(char buffer[], int capacity, LPCSTR utf8data)
{
	UINT codePage = CP_ACP;
	int charLength;
	int ret = -1;
	wchar_t * utf16data;

	// Prevent buffer overflow issue for sake of security
    int utf16Length = MultiByteToWideChar(
        CP_UTF8,		// source string is in UTF-8
		0,				// conversion flags
        utf8data,		// source UTF-8 string pointer
		-1,				// NUL-terminiated
        NULL,			// unused - no conversion done in this step
        0				// request size of destination buffer, in wchar_ts
    );
	//
	if (utf16Length <= 0)
	{
		ret = (int)GetLastError();
		return -ret;	//  ERROR_NO_UNICODE_TRANSLATION     1113L
	}

	utf16data = (wchar_t *)LocalAlloc(LPTR, sizeof(wchar_t *) * utf16Length);
	if(utf16data == NULL)
		return ret;

    // Do the actual conversion from UTF-8 to UTF-16
    if(MultiByteToWideChar(
        CP_UTF8,		// source string is in UTF-8
		0,				// conversion flags
        utf8data,		// source UTF-8 string pointer
		-1,				// NUL-terminiated
		utf16data,		// pointer to destination buffer
        utf16Length		// size of destination buffer, in wchar_ts           
		) <= 0)
	{
		goto l_bailout;
	}

	// convert back to MBCS again. this time it is in system default ANSI/MBCS
	// Prevent buffer overflow issue for sake of security
    charLength = WideCharToMultiByte(
		codePage,
		0,				// conversion flags
        utf16data,		// source UTF-16 string
        utf16Length,	// length of the source string, in wchar_ts
        NULL,			// unused - no conversion required in this step
        0,				// request size of destination buffer, in chars
        NULL, NULL
    );

	if (charLength > capacity)
		goto l_bailout;

	if (charLength <= 0)
	{
		ret = -(int)GetLastError();
		goto l_bailout;
	}

	// Do the actual conversion from UTF-16 to local MBCS
	ret = WideCharToMultiByte(
		codePage,
		0,				// conversion flags
        utf16data,		// source UTF-16 string
		utf16Length,	// length of the source string, in wchar_ts
		(LPSTR)buffer,	// pointer to destination buffer
		charLength,		// size of destination buffer, in chars
        NULL, NULL
    );

l_bailout:
	LocalFree((HLOCAL)utf16data);
	return ret;
}