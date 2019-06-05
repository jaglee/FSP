# Flexible Session Protocol
https://datatracker.ietf.org/doc/draft-gao-flexible-session-protocol/

### Abstract

FSP is a connection-oriented transport layer protocol that provides mobility, multihoming and multipath support by introducing the concept of 'upper layer thread ID', which was firstly suggested in "Fuzzy-layering and its suggestion" (IETF Mail Archive, September 2002, https://mailarchive.ietf.org/arch/msg/ietf/u-6i-6f-Etuvh80-SUuRbSCDTwg).

Authencity of an FSP packet is usually crytographically protected by some algorithm that requires a shared secret key. The upper layer thread ID is assigned roughly the same semantics as the Security Parameter Index (SPI) in MOBIKE [RFC4555] to index the local context of the security association. The local context of the security association is initialized by the FSP layer, and enhanced by the upper layer application which SHALL install the secret key.

FSP facilitates such secret key installation by introducing the concept of 'transmit transaction', which makes it flexible for the application layer protocols to adopt wide range of key establishment algorithm.

### Features
##### Alleviation, if not elimination, of the routing scalability problem
By providing mobility and multihoming support at the transport layer, resisting against connection redirection by authenticating each FSP packet.

##### Programmer-friendly security support
By
- enabling expert programmers to devise user-space application-charactered authenticated key establishment mechanism
- providing ubiquitous encryption and/or authentication of data
- utilizing only one symmetric-key algorithm in each FSP 'major', preventing daily programming practicers from risking choice anxiety
The symmetric-key algorithm chosen shall be well studied, standardized, with hardware acceleration mechanism widely available.

##### Transmit transaction 
Introduction of the transmit transaction concept at the transport layer keeps the byte stream transmission style alike TCP while provides straightforward means to delimit messages, such as continual requests or responses in the typical client server application, the web application based on HTTP/HTTPS. It is deemed to be more efficient than exploiting delimiters such as CR-LF pair in the application layer.

##### Flexibility of key establishment
By embedding a quad-party key installation sub-protocol to facilitate application of the key established through some cryptography algorithm utilized or devised at the application layer.

##### Zero round-trip connection cloning to avoid head-of-line blocking
By providing a sub-protocol to 'multiply' the root connection of the FSP session.

##### Hybrid traffic class support
Hybrid traffic class support is that FSP is able to transport both wine-like payload and milk-like payload in one group of connections. The group of connections consists of one root connection and a number of clone connections.

Wine-like payload is traditional in the sense that the carrier shall favor older packet. Milk-like payload is that the carrier shall keep the newer packet, discards the older one if the buffer overflows somewhere.

The payload of the root connection MUST be wine-like while the payload of a clone connection MAY be either wine-like or milk-like.
