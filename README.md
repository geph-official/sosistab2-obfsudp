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

Initial handshake frames are _symmetrically_ encrypted by keys derived from the server's X25519 public key. The intention here is that only people who know the server's public key `server_pk` (i.e. not ISP snoopers) can derive these keys:

- `hs_c2s`: the client-to-server handshake key, derived as `hs_c2s = derive_key("sosistab-2-c2s", server_pk)`, where `derive_key` is the key derivation function defined by BLAKE3.
- `hs_s2c`: the server-to-server handshake key, derived as `hs_s2c = derive_key("sosistab-2-s2c", server_pk)`.

Handshake frames are stdcode-encoded and encrypted representations of this Rust enum:

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
  - `sess_key`: symmetric key derived from triple-ECDH between the client keys and the server keys
  - `timestamp`: current timestamp as Unix seconds
  - `version`: set to 4
- `client_commitment`: `blake3(client_hello)`

The session key is derived as `sess_key = blake3_keyed(key = blake3(metadata), shared_secret)`, where `metadata` is the `metadata` field in the ClientHello and `shared_secret` is the shared-secret derived from the triple-ECDH key exchange.

At this point, the server does not save information into any sort of table or similar. It throws away all the values calculated and continues processing more incoming packets.

**The server must take care to reject replayed ClientHellos**. This is done by:

- Remembering the last 60 seconds of ClientHellos, and rejecting any duplicates
- Rejecting any ClientHello with timestamp earlier than or later than 30 seconds from the present

### Finalize

The client receives the ServerHello and verifies that:

- `long_pk` is the expected value
- `client_commitment` matches its own, computed as `blake3(client_hello)`

It then calculates the session key `sess_key` using triple-ECDH, and sends the Finalize message containing

- `resume_token`: the `resume_token` from the ServerHello
- `metadata`: arbitrary metadata related to this connection. This is typically used to indicate which higher-level sosistab2 Multiplex this pipe belongs to.

At this point, both client and server have agreed on the same `sess_key`. Both now derive:

- `up_key = blake3_keyed(key = "upload--------------------------", sess_key)`: the upload key
- `dn_key = blake3_keyed(key = "download------------------------", sess_key)`: the download key

## "Steady state" frames

Once the session is established, both sides have the other's host:port, as well as an upload symmetric key and download symmetric key. They now send frames of the format `(u64, SessionFrame)`, stdcode-serialized and encrypted with the right key (e.g. an upload message `m` will be sent as `seal(up_key, m)`):

```rust
pub enum SessionFrame {
    Data {
        seqno: u64,
        body: Bytes,
    },
    Parity {
        data_frame_first: u64,
        data_count: u8,
        parity_count: u8,
        parity_index: u8,
        pad_size: u16,
        body: Bytes,
    },
    Acks {
        acks: Vec<(u64, u32)>,
        naks: Vec<u64>,
    },
}

```

The `u64` attached to the SessionFrame increases by 1 for every sent packet, and the receiver must use this to implement replay attack prevention.

We discuss the three kinds of frames separately:

### Data frames

Whenever a datagram needs to be sent, it's **fragmented** and encoded into one or more `Data` frames. This is because we must support datagrams of up to 64 KiB, which is much larger than the typical MTU on Internet links.

Every datagram is split into fragments of the format:

- 1 byte: which fragment is this
- 1 byte: total number of fragments
- up to 1340 bytes: the content of the fragment

For example, a datagram of 12345 bytes will be split into 10 fragments, with the first fragment containing the header `00 19` and the first 1340 bytes of the datagram, the second fragment containing the header `09 19` and the next 1340 bytes, and so on. These fragments will then individually be encoded as bodies of `Data` frames.

### Parity frames

Parity frames are use for forward error correction (FEC), based on 8-bit Reed-Solomon. The important thing to note here is that the sender of data **does not** pick which Reed-Solomon encoding to use beforehand (say, expand 5 data frames to 5 data + 3 parity). Instead, it only needs to pick the encoding once it decides to send parity frames, and at that point dynamically change the encoding.

This is reflected in the format of the parity frames. Each parity frame essentially "claims" certain data frames as part of the Reed-Solomon encoded group:

- `data_frame_first`: The sequence number of the first data frame included in the parity calculation.
- `data_count`: The number of data frames included in the calculation.
- `parity_count`: The total number of parity frames for the group.
- `parity_index`: This parity frame's index. (e.g. 0 means this is the first parity frame)
- `pad_size`: The uniform size that all of the frames must be padded to, for Reed-Solomon decoding (note that RS requires every data and parity packet to be the same size)
- `body`: The parity data itself.

### Ack frames

Because `obfsudp` is an unreliable datagram transport, acknowledgements are not used for retransmission or congestion control. Instead, they are simply used to help the other end measure connection quality. The format of an ack frame is as follows:

- `acks`: a vector of acknowledged `seqno`s that were received by this sender, associated with _the number of milliseconds between when that `seqno` was received and when the ack is sent_. Including the latter number allows the packet receivers to freely delay and batch acks without affecting the sender's ping measurements.
  = `naks`: a vector of `seqno`s that the sender believes are lost forever, calculated by heuristics such as the number of subsequent `seqno`s confirmed to arrive.
