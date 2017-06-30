
# FSP
## A concept implementation of Flexible Session Protocol

### Abstract

FSP is a connection-oriented transport layer protocol that provides mobility, multihoming and multipath support by introducing the concept of 'upper layer thread ID', which was firstly suggested in [Gao2002].

Authencity of an FSP packet is usually crytographically protected by some algorithm that requires a shared secret key. The upper layer thread ID is assigned roughly the same semantics as the Security Parameter Index (SPI) in MOBIKE [RFC4555] to index the secret key. The secret key is assumed to be installed by the upper layer application. 

FSP facilitates such secret key installation by introducing the concept of 'transmit transaction', which makes it flexible for the application layer protocols to adopt wide range of key establishment algorithm.

#### Introduction

Flexible Session Protocol is a connection-oriented transport layer provides mobility, multihoming and multipath support by introducing the concept of 'upper layer thread ID' (ULTID), which was firstly suggested in [Gao2002]. One FSP connection MAY associate with up to 4 lower layer addresses. Besides the IP addresses associated with an FSP connection MAY change after the FSP connection is established.
When FSP is applied over IPv6 networks, the lower layer addresses SHALL be IPv6. The rightmost 32 bits of each IPv6 address is designated as the the ULTID which MUST keep unchanged across IPv6 address migration or translation. The leftmost 96 bits still holds the routing locator semantics. It can be argued that the routing scalability problem in the IPv6 network is effectively eliminated by such tuning of IPv6.

An integrity check code (ICC) field associated with the ULTID is designed in the FSP header to protect authencity and optionally privacy of the FSP packet. An FSP packet is assumed to originate from the same source if the ICC value associated with certain destination ULTID passes validation, regardless of the source or destination address in the underlying layer.

ICC is either calculated by [CRC64] which protects FSP against unintended modification, or crytographically calculated with some Authenticated Encryption with Additional Data ([R01]) algorithm (for current version of FSP the algorithm chosen is [AES]-[GCM]) or a cryptographic hash function (for current version of FSP it is BLAKE2 [RFC7693]) that requires a shared secret key. In the latter case the ULTID is assigned roughly the same semantics with Security Parameter Index (SPI) in MOBIKE [RFC4555]. The shared secret key is indexed by the source or destination ULTID in the local context of the sender or the receiver, respectively.

The shared secret key is assumed to be installed by the upper layer application (ULA). FSP facilitates such key installation by introducing the concept of 'transmit transaction'. Mechanism to facilitate transmit transaction also provides the 'session-connection synchronization' service to the upper layer.

FSP is a transport layer protocol as specified in [RFC1122], provides services alike TCP [STD5] to ULA, with session layer features as suggested in [OSI/RM], most noticeably 'session-connection synchronization'. It can be argued that FSP makes it flexible for the application layer protocols to adopt much wider range of key establishment protocol/algorithm while offloading routine authentication and optionally encryption of the data to the underlying layers where it may be much easier to exploit hardware-acceleration.

##### Mobility support
At present, mobility, multihoming and multipath issues are active concerns in the Internet research and development community. FSP directly supports node mobility and node multihoming, indirectly support multipath and site multihoming.

To make mobility support work reasonably stable it is assumed that one end-node MUST keep its lower layer address reasonably stable while the other end-node SHOULD NOT change its lower layer address too frequently so that the packet to inform the remote end to update the lower layer address association could reach its destination in a satisfying success rate. Thus FSP solves somewhat coarse-grain or low-speed mobility problem. Fine-grain or high-speed mobility is left to the underlying physical network. Here 'physical network' has semantics specified in [RFC1122].

It can be argued in the prevailing cloud-computing scenarios and the emerging Internet of Things use cases such assumption is naturally held.

##### Resistance against connection redirection
To defend against possible connection redirection or dirty data injection (message insertion, deletion, modification and replaying), each FSP connection prepares a pair of ULTIDs. An ULTID is assigned roughly the same semantics with the Security Parameter Index (SPI) in MOBIKE [RFC4555].

An integrity check code (ICC) field is designed in FSP header to protect authencity and optionally privacy of the FSP packet.
On initiating FSP takes use of [CRC64] to make checksum of the FSP packet to protect it against unintentional modification. The checksum is taken as the ICC.

After the ULA has installed a secret key, value of ICC is calculated by firstly getting the secret key associated with the local ULTID, then calculating the tag value with the AES-GCM [GCM] authenticated encryption with additional data algorithm [R01], or calculating the message authentication code with the BLAKE2 algorithm [RFC7693].

FSP facilitates secret key installation by introducing the concept of 'transmit transaction'.

An ULTID is effective in the local context of an FSP connection only. The source ULTID and the destination ULTID of an FSP packet usually differ in their values. However the secret keys indexed in the local contexts of the two end-points must have the same value.

##### Ubiquitous encryption and/or authentication of data
It assumes that in the scenarios applying FSP it is the ULA to do key establishment and/or end-point authentication while the FSP layer provides authenticated, optionally encrypted data transfer service. Together they establish a secure channel between two application end-points.

#The ULA SHOULD install a shared secret key as soon as possible. Whenever the new secret key is installed, by default FSP utilize a pre-determined Authenticated Encryption with Additional Data (AEAD) algorithm to protect both authencity of the full FSP packet and privacy of the payload. In this FSP version the algorithm chosen is AES-GCM. 

Optionally the ULA MAY make FSP to just apply message authentication code (MAC) generation and verification. In this version the algorithm chosen to generate and verify the MAC is BLAKE2 (RFC7693). Typically when the ULA does its own stream encryption it chooses this option.

##### Flexibility of Key Establishment
Transmit transaction is introduced in FSP to facilitate ULA to do end-point authentication and/or key extablishment. A dedicate application program interface (API) is designed for the ULA to install the secret key established by the ULA. 

A flag called 'End of Transaction' (EoT) is designed in the FSP header. When it is set, it marks that the transmit transaction in the direction from the source of the FSP packet towards the destination of the FSP packet is committed.

By committing a transmit transaction the ULA clearly tells the underlying FSP layer that the next packet sent MAY adopt a new secret key. The ULA SHOULD install a new secret key instantly after it has committed a transmit transaction. After the ULA install a new secret key 
#every packet sent later than the one with the EoT flag set MUST adopt the new secret key. 

On receiving an FSP packet with the EoT flag set the ULA is informed that the next packet received MAY adopt a new shared secret key. The ULA SHOULD have installed the new shared secret key, or install it instally after accepting the packet with the EoT flag set. If the new secret key has ever been installed the packet received after the one with the EoT flag set MUST adopt the new secret key.

In a typical scenario the ULA endpoints first setup the FSP connection where resistance against connection redirection is  weakly endorsed by CRC64. After the pair of ULA endpoints establish a shared secret key, install the secret key and commit current transmit transactions, authencity of the FSP packets sent later are crytographically protected and resistence against various attacks is secured.
The shared secret key could be derived from a preshared secret, where zero round-trip of initial data packet is required. The key could be generated by the initiator side of the FSP connection and transported to the responder side by encrypted it in the public key which may be published in the payload piggybacked on the acknowledgment packet of the FSP connection request packet. Of course it could be agreed by the participants after a few round-trips of data packets were exchanged as well.

It is flexible for the application layer protocols to adopt much wider range of key establishment algorithm while offloading routine authentication and optionally encryption of the data to the underlying layers where it may be much easier to exploit hardware-acceleration.

##### Elimination of IPv6 routing scalability problem
To utilize IPv6 address space more efficiently FSP makes some slight tuning of address architecture when working over the IPv6 network. In an IPv6 packet that carries FSP payload each of the source and destination 128-bit IPv6 address is split into three parts: the 64-bit network prefix, the 32-bit aggregation host id and the 32-bit ULTID. 

It requires some further subtle tuning of the IPv6 architecture:
o Each physically network interface that has IPv6 address configured SHALL NOT have the network prefix configured longer than 96 bits, no matter that the IPv6 address is assigned by Stateless Address Autoconfiguration ([RFC4862]), stateful Dynamic Host Configuration Protocol for IPv6 ([RFC3315], [RFC3633]) or by some other means.

o The ULA is the ultimate IPv6 end-point.
o Every network node is effectively a router. Especially when FSP over UDP in the IPv4 network is exploited the two end point host nodes are treated as if they were routers connecting the IPv6 addressed ULAs across the IPv4 network.
o Whenever an IPv6 interface is reconfigured, the higher 64 bits of any IPv6 address MAY change freely, the middle 32 bits SHOULD be stable while the lower 32 bits MUST keep unmodified.
And thus it may be argued that the routing scalability problem does not exist at all for FSP over such tuned IPv6.

##### Zero round-trip connection cloning
An FSP connection MAY be multiplied to get a clone or clones of the connection. In this version of FSP a clone connection MAY NOT be cloned further, and only the connection where authencity of the packets is crytographically protected may be multiplied.
The packet that carries the command to multiply an established FSP connection MUST be sent from a new allocated local ULTID towards the destination ULTID of the cloned connection. It is an out-of-band packet in the context of the cloned connection and it MUST be crytographically protected by the secret key of the cloned connection. The packet MAY carry payload as it usually does.
The receiver of the packet MUST allocate a new local ULTID, accept the optional payload in the new context associated with the new ULTID, derive a new secret key from the secret key of the cloned connection, and responds from the new context. The response MAY carry payload as it usually does. The very first response packet MUST be protected by the new secret key. The sender of the multiply command packet MUST automatically inaugurate the same secret key, derived from the secret key of the same cloned connection. And it MUST treat the response packet as though a transmit transaction have been committed by the responder, i.e. authencity of the response packet is verified with the new secret key.
Thus the new clone connection is established at a new pair of ULTIDs with zero round-trip overhead. This mechanism may be exploited to provide expedited data transfer service or parallel data transfer.

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
