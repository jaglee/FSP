# Flexible Session Protocol
https://www.ietf.org/id/draft-jason-fsp-00.txt

### Abstract

FSP is a connection-oriented transport layer protocol that provides mobility, multihoming and multipath support by introducing the concept of 'upper layer thread ID', which was firstly suggested in [Gao2002].

Authencity of an FSP packet is usually crytographically protected by some algorithm that requires a shared secret key. The upper layer thread ID is assigned roughly the same semantics as the Security Parameter Index (SPI) in MOBIKE [RFC4555] to index the secret key. The secret key is assumed to be installed by the upper layer application. 

FSP facilitates such secret key installation by introducing the concept of 'transmit transaction', which makes it flexible for the application layer protocols to adopt wide range of key establishment algorithm.

### Features
##### Mobility support
##### Resistance against connection redirection
##### Ubiquitous encryption and/or authentication of data
##### Flexibility of Key Establishment
##### Elimination of IPv6 routing scalability problem
##### Zero round-trip connection cloning

#### Normative References
[STD5]		Postel, J., "Internet Protocol", STD 5, RFC 791, September 1981.

[STD6]		Postel, J., "User Datagram Protocol", STD 6, RFC 768, August 1980.

[STD7]	  Postel, J., "Transmission Control Protocol", STD 7, RFC 793, September 1981.

[OSI/RM]		ISO and IEC, "Information technology-Open Systems Interconnection - Basic Reference Model: The Basic Model", ISO/IEC 7498-1 Second edition, November 1994. <https://www.iso.org/standard/20269.html>
<http://standards.iso.org/ittf/PubliclyAvailableStandards/s014258_ISO_IEC_7498-4_1989(E).zip>

[RFC1122]	Braden, R., Ed., "Requirements for Internet Hosts - Communication Layers", STD 3, RFC 1122, October 1989.

[RFC2119]	Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.

[RFC2460]	Deering, S. and Hinden, R., "Internet Protocol, Version 6 (IPv6) Specification", RFC 2460, December 1998.

[R01]		Rogaway, P., "Authenticated encryption with Associated-Data", ACM Conference on Computer and Communication Security (CCS'02), pp. 98-107, ACM Press, 2002.

[RFC3629]	Yergeau, F., "UTF-8, a transformation format of ISO 10646", STD 63, RFC 3629, November 2003.

[RFC4291]	Hinden, R. and Deering S., "IP Version 6 Addressing Architecture", RFC 4291, February 2006. 

[RFC5226]	Narten, T. and H. Alvestrand, "Guidelines for Writing an IANA Considerations Section in RFCs", BCP 26, RFC 5226, May 2008.

[RFC7693] Saarinen, M-J., Ed. and Aumasson, J-P., "The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)", RFC 7693, November 2015.

[AES]		NIST, "Advanced Encryption Standard (AES)", November 2001. <https://doi.org/10.6028/NIST.FIPS.197>

[GCM]		NIST, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC", November 2007. <http://dx.doi.org/10.6028/NIST.SP.800-38D>

[CRC64]		ECMA, "Data Interchange on 12.7 mm 48-Track Magnetic Tape Cartridges - DLT1 Format Standard, Annex B", ECMA-182, December 1992.

#### Informative References

[Gao2002]	Gao, J., "Fuzzy-layering and its suggestion", IETF Mail Archive, September 2002, https://mailarchive.ietf.org/arch/msg/ietf/u-6i-6f-Etuvh80-SUuRbSCDTwg

...

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
