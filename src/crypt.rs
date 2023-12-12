use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};

use bytes::Bytes;

use chacha20poly1305::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use replay_filter::ReplayFilter;

use sosistab2::crypt::AeadError;
use stdcode::StdcodeSerializeExt;

use super::frame::ObfsUdpFrame;

/// An encrypter of obfuscated packets, with an anti-replay counter.
#[derive(Clone)]
pub struct CounterEncrypter {
    inner: ObfsAead,
    seqno: Arc<AtomicU64>,
}

impl CounterEncrypter {
    pub fn new(inner: ObfsAead) -> Self {
        Self {
            inner,
            seqno: Default::default(),
        }
    }

    /// Encrypts a packet.
    pub fn encrypt(&self, pkt: &ObfsUdpFrame) -> Bytes {
        let seqno = self.seqno.fetch_add(1, Ordering::SeqCst);
        let ptext = (seqno, &pkt).stdcode();

        self.inner.encrypt(&ptext)
    }
}

/// A decrypter of obfuscated packet, that checks the anti-replay counter.
#[derive(Clone)]
pub struct CounterDecrypter {
    inner: ObfsAead,
    dedupe: Arc<Mutex<ReplayFilter>>,
}

impl CounterDecrypter {
    pub fn new(inner: ObfsAead) -> Self {
        Self {
            inner,
            dedupe: Arc::new(Mutex::new(ReplayFilter::default())),
        }
    }

    /// Decrypts a packet.
    pub fn decrypt(&self, b: &[u8]) -> anyhow::Result<ObfsUdpFrame> {
        let ptext = self.inner.decrypt(b)?;
        let (outer_seqno, frame): (u64, ObfsUdpFrame) = stdcode::deserialize(&ptext)?;
        log::trace!("outer_seqno {outer_seqno}");
        if !self.dedupe.lock().add(outer_seqno) {
            anyhow::bail!("rejecting duplicate outer_seqno {outer_seqno}")
        }
        Ok(frame)
    }
}

/// AEAD where the messages produced are "uniform" in appearance.
#[derive(Clone)]
pub struct ObfsAead {
    key: Arc<ChaCha20Poly1305>,
    max_len: Arc<AtomicUsize>,
}

impl ObfsAead {
    pub fn new(key: &[u8; 32]) -> Self {
        let aead_key = Key::from_slice(key); // Create a key from the slice
        let cipher = ChaCha20Poly1305::new(aead_key); // Create a new instance of ChaCha20Poly1305
        Self {
            key: Arc::new(cipher),
            max_len: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Encrypts a message with a random nonce.
    pub fn encrypt(&self, msg: &[u8]) -> Bytes {
        let mut nonce = [0; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        // make an output. the padding is placed in the beginning.
        let minimum_len = msg.len() + 1 + 12 + 16;
        let max_len = self
            .max_len
            .fetch_max(minimum_len, Ordering::Relaxed)
            .max(minimum_len);
        let target_len = rand::thread_rng()
            .gen_range(minimum_len, max_len + 1)
            .min(minimum_len + 255);
        let padding_len = target_len - minimum_len;
        let mut padded_msg = Vec::with_capacity(target_len);
        padded_msg.push(padding_len as u8);
        padded_msg.resize(padding_len + 1, 0xff);
        padded_msg.extend_from_slice(msg);

        // now we overwrite it
        let nonce = Nonce::from_slice(&nonce); // Create a nonce from the slice
        self.key
            .encrypt_in_place(nonce, b"", &mut padded_msg) // Encrypt in place using the key and nonce
            .expect("encryption failure!");

        padded_msg.extend_from_slice(nonce.as_slice());

        assert_eq!(padded_msg.len(), target_len);
        padded_msg.into()
    }

    /// Decrypts a message.
    pub fn decrypt(&self, ctext: &[u8]) -> Result<Bytes, AeadError> {
        if ctext.len() < 12 + 16 {
            return Err(AeadError::BadLength);
        }
        let (cytext, nonce) = ctext.split_at(ctext.len() - 12);
        let mut ctext = cytext.to_vec();
        let nonce = Nonce::from_slice(nonce); // Create a nonce from the slice

        // Decrypt in place, this will also verify the tag
        self.key
            .decrypt_in_place(nonce, b"", &mut ctext)
            .map_err(|_| AeadError::DecryptionFailure)?;

        let padding_len = ctext[0] as usize;
        if padding_len + 1 > ctext.len() {
            return Err(AeadError::BadLength);
        }
        Ok(Bytes::from(ctext).slice((padding_len + 1)..))
    }
}

/// A triple-ECDH handshake.
pub fn triple_ecdh(
    my_long_sk: &x25519_dalek::StaticSecret,
    my_eph_sk: &x25519_dalek::StaticSecret,
    their_long_pk: &x25519_dalek::PublicKey,
    their_eph_pk: &x25519_dalek::PublicKey,
) -> blake3::Hash {
    let g_e_a = my_eph_sk.diffie_hellman(their_long_pk);
    let g_a_e = my_long_sk.diffie_hellman(their_eph_pk);
    let g_e_e = my_eph_sk.diffie_hellman(their_eph_pk);
    let to_hash = {
        let mut to_hash = Vec::new();
        if g_e_a.as_bytes() < g_a_e.as_bytes() {
            to_hash.extend_from_slice(g_e_a.as_bytes());
            to_hash.extend_from_slice(g_a_e.as_bytes());
        } else {
            to_hash.extend_from_slice(g_a_e.as_bytes());
            to_hash.extend_from_slice(g_e_a.as_bytes());
        }
        to_hash.extend_from_slice(g_e_e.as_bytes());
        to_hash
    };
    blake3::hash(&to_hash)
}

const CLIENT_UP_KEY: &[u8; 32] = b"upload--------------------------";
const CLIENT_DN_KEY: &[u8; 32] = b"download------------------------";

pub fn upify_shared_secret(shared_secret: &[u8]) -> blake3::Hash {
    blake3::keyed_hash(CLIENT_UP_KEY, shared_secret)
}
pub fn dnify_shared_secret(shared_secret: &[u8]) -> blake3::Hash {
    blake3::keyed_hash(CLIENT_DN_KEY, shared_secret)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfs_aead_encrypt_decrypt() {
        // Generate a random 256-bit key
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);

        let obfs_aead = ObfsAead::new(&key);

        // Generate a random test message
        for _ in 0..100 {
            let mut msg = vec![0u8; rand::thread_rng().gen_range(0, 20)];
            rand::thread_rng().fill_bytes(&mut msg);

            // Encrypt the test message
            let encrypted_msg = obfs_aead.encrypt(&msg);

            // Decrypt the encrypted message
            let decrypted_result = obfs_aead.decrypt(&encrypted_msg).unwrap();
            assert_eq!(&decrypted_result[..], &msg);
        }
    }

    #[test]
    fn test_replay_protection() {
        // Generate a random key
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);

        // Create an ObfsAead instance for encryption/decryption
        let obfs_aead = ObfsAead::new(&key);

        // Create a CounterEncrypter instance
        let counter_encrypter = CounterEncrypter::new(obfs_aead.clone());

        // Create an ObfsDecrypter instance
        let obfs_decrypter = CounterDecrypter::new(obfs_aead.clone());

        // Create a test frame with random data
        let test_frame = ObfsUdpFrame::Data {
            seqno: 0, // This will be overridden by the CounterEncrypter
            body: Bytes::from_iter(std::iter::repeat_with(rand::random::<u8>).take(50)),
        };

        // Encrypt the frame to produce a message
        let encrypted_msg = counter_encrypter.encrypt(&test_frame);

        // Decrypt the message for the first time, this should succeed
        let decrypted_frame_result = obfs_decrypter.decrypt(&encrypted_msg);
        assert!(decrypted_frame_result.is_ok());

        // Attempt to decrypt the message a second time, this should fail
        let replay_result = obfs_decrypter.decrypt(&encrypted_msg);
        assert!(replay_result.is_err());

        // To be thorough, we could also check that the error is specifically about the replay attack
        match replay_result {
            Err(err) => assert!(err.to_string().contains("rejecting duplicate outer_seqno")),
            _ => panic!("Expected an error for replayed message, but got successful decryption"),
        }
    }
}
