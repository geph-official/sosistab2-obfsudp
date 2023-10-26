# an obfuscated UDP transport for sosistab2

`sosistab2-obfsudp` is an obfuscated, unreliable, connection-oriented protocol built on top of UDP, intended to be used as a backend "pipe" for sosistab2.

It allows servers to listen for pipes, and clients to connect to servers and establish pipes, with a TCP-like API, but the pipes themselves carry unreliable datagrams up to 64 KB in size.

The obfuscation is intended to achieve:

- Resistance to passive analysis: given a packet trace, it's difficult to tell which packets are `obfsudp` packets.
- Resistance to active probing: given a `host:port`, as well as observation of all packets to and from it, it's difficult to devise a test that will confirm whether or not it is hosting an `obfsudp` server.
- Resistance to packet manipulation and injection: both of the above hold true even if attackers can arbitrarily corrupt and inject packets of their own.

# Specification

## Encryption format

All UDP packets sent by obfsudp are encrypted with the following
