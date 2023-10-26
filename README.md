# an obfuscated UDP transport for sosistab2

`sosistab2-obfsudp` is an obfuscated, unreliable, connection-oriented protocol built on top of UDP, intended to be used as a backend "pipe" for sosistab2.

It allows servers to listen for pipes, and clients to connect to servers and establish pipes, with a TCP-like API, but the pipes themselves carry unreliable datagrams up to 64 KB in size.

The obfuscation is intended to achieve:

- Resistance to passive analysis: given a packet trace, it's difficult to tell which packets are `obfsudp` packets.
- Resistance to active probing: given a `host:port`, as well as observation of all packets to and from it, it's difficult to devise a test that will confirm whether or not it is hosting an `obfsudp` server.
- Resistance to packet manipulation and injection: both of the above hold true even if attackers can arbitrarily corrupt and inject packets of their own.

# Specification

## Encryption format

All UDP packets sent by obfsudp are encrypted using ChaCha20-Poly1305 in a way that looks uniformly random and hides the original packet length.

An encrypted packet encrypted to the key `k` looks like this:

- Encrypted with ChaCha20-Poly1305 with key `k` and nonce `n`:
  - 1 byte: padding length `padlen`
  - `padlen` bytes: arbitrary padding bytes
  - variable length: message
- 12 bytes: random nonce `n`, separately chosen for every packet

We notate encrypting a message `m` with key `k` and a random nonce as `seal(k, m)`, and decryption as `open(k, m)`

## Initial handshake

Initial handshake messages are _symmetrically_ encrypted by keys derived from the server's X25519 public key. The intention here is that only people who know the server's public key `server_pk` (i.e. not ISP snoopers) can derive these keys:

- `hs_c2s`: the client-to-server handshake key, derived as `hs_c2s = derive_key("sosistab-2-c2s", server_pk)`, where `derive_key` is the key derivation function defined by BLAKE3.
- `hs_s2c`: the server-to-server handshake key, derived as `hs_s2c = derive_key("sosistab-2-s2c", server_pk)`.

Handshake messages are stdcode-encoded and encrypted representations of this Rust enum:

```rust
pub enum HandshakeFrame {
    ClientHello {
        long_pk: x25519_dalek::PublicKey,
        eph_pk: x25519_dalek::PublicKey,
        version: u64,
        timestamp: u64,
    },
    ServerHello {
        long_pk: x25519_dalek::PublicKey,
        eph_pk: x25519_dalek::PublicKey,
        resume_token: Bytes,
        client_commitment: [u8; 32],
    },
    Finalize {
        resume_token: Bytes,
        metadata: String,
    },
}
```

There are three phases to the handshake that establishes an `obfsudp` connection: client hello, server hello, and finalize.

### Client hello

The client obtains two X25519 keypairs:

- `long_sk`, `long_pk`: a "long-term" keypair, used to uniquely identify the client. May be randomly generated if the client does not need to authenticate through this handshake.
- `eph_sk`, `eph_pk`: an ephemeral keypair. Must be freshly randomly generated.

then sends `seal(hs_c2s, client_hello)` to the server, where `client_hello` is filled with the keypairs, `version = 4` and `timestamp` being the current Unix timestamp in seconds.

### Server hello

The server responds with a ServerHello containing:

- `long_pk`: its long term, well-known X25519 public key
- `eph_pk`: its ephemeral X25519 public key
- `resume_token`: a "cookie" that allows the server to reconstruct all the information it needs to initialize the session. Currently, that is the following data, encrypted in such a way that only the server itself and decrypt it:
  - `sess_key`: symmetric key derived from the triple-ECDH handshake between the client keys and the server keys
  - `timestamp`: current timestamp as Unix seconds
  - `version`: set to 4
- `client_commitment`: `blake3(client_hello)`

**The server must take care to reject replayed ClientHellos**. This is done by:

- Remembering the last 60 seconds of ClientHellos, and rejecting any duplicates
- Rejecting any ClientHello with timestamp earlier than or later than 30 seconds from the present
