## How to compile conceptual implementation of Flexible Session Protocol

This project roughly implements core concepts of FSP, written in Microsoft Visual Studio 2012/2015/2017, targeting at Windows 7 and above version.  It implements FSP by split the core functions across two sub-layers: the Lower Layer Service and the Dynamic Linked Library.  The core source codes are put into two directories, FSP_SRV and FSP_DLL, respectively. 

FSP_SRV implements the Lower Layer Service (LLS). When compiled targeting at Win32, it implements FSP over UDP/IPv4. When compiled targeting  at x64, it implements FSP over IPv6. However, FSP connection number in IPv6 network is limitted. LLS means to implement function modules that are expected to be hardware-accelerated or implemented in the kernel.

If compiling to target at Win32, Microsoft Visual Studio 2012 Desktop Edition should work. If compiling to target at x64, it requires Microsoft Visual Studio 2015 Communitity Edition or above version. The solution file to open is FSP.sln.

FSP_DLL implements the Dynamic Linked Library part of the conceptual implementation. DLL means to implement function modules that relate to application programming interface, buffer management, data delivery  and optionally on-the-wire compression (not included in the source code committed yet).

Currently the DLL is targeting at Win32 only. It requires Microsoft Visual Studio 2012 or versions above. Desktop Edition or Communitity Edition works. The solution file to open is FSP_FileSync.sln

The solution file FSP_FileSync.sln also includes two test projects that should work together with the DLL: FileSyncClient and FileSyncServer. When compiling in Debug mode, the solution tests FSP over UDP/IPv4. When compiling in Release mode, the solution tests FSP over IPv6.

It should work as well if upgrading FSP_FileSync.sln to Visual Studio 2017 edition and compiling to target at x64.

Please note that the macro OVER_UDP_IPv4 shall be predefined both in the FSP_SRV project and the FSP_DLL project if to test FSP over UDP/IPv4, and it shall be neither defined in the FSP_SRV project nor in the FSP_DLL project if to test FSP over IPv6.

##### Visual Studio is the trademark of Microsoft.
