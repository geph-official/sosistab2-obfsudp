use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};

use bytes::Bytes;

use rand::{Rng, RngCore};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use sosistab2::crypt::AeadError;
use stdcode::StdcodeSerializeExt;

use super::frame::ObfsUdpFrame;

/// An encrypter of obfuscated packets.
#[derive(Clone)]
pub struct ObfsEncrypter {
    inner: ObfsAead,
    seqno: Arc<AtomicU64>,
}

impl ObfsEncrypter {
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

/// A decrypter of obfuscated packets.
#[derive(Clone)]
pub struct ObfsDecrypter {
    inner: ObfsAead,
    dedupe: Arc<AtomicU64>,
}

impl ObfsDecrypter {
    pub fn new(inner: ObfsAead) -> Self {
        Self {
            inner,
            dedupe: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Decrypts a packet.
    pub fn decrypt(&self, b: &[u8]) -> anyhow::Result<ObfsUdpFrame> {
        let ptext = self.inner.decrypt(b)?;
        let (outer_seqno, frame): (u64, ObfsUdpFrame) = stdcode::deserialize(&ptext)?;
        if self.dedupe.fetch_max(outer_seqno, Ordering::SeqCst) >= outer_seqno {
            anyhow::bail!("rejecting out-of-order outer_seqno {outer_seqno}")
        }
        Ok(frame)
    }
}

/// AEAD where the messages produced are "uniform" in appearance.
#[derive(Debug, Clone)]
pub struct ObfsAead {
    key: Arc<LessSafeKey>,
    max_len: Arc<AtomicUsize>,
}

impl ObfsAead {
    pub fn new(key: &[u8]) -> Self {
        let ubk = UnboundKey::new(&CHACHA20_POLY1305, key).unwrap();
        Self {
            key: Arc::new(LessSafeKey::new(ubk)),
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
        let target_len = if msg.len() > 1300 {
            minimum_len
        } else {
            rand::thread_rng().gen_range(minimum_len, max_len + 1)
        }
        .min(minimum_len + 255);
        let padding_len = target_len - minimum_len;
        let mut padded_msg = Vec::with_capacity(target_len);
        padded_msg.push(padding_len as u8);
        padded_msg.resize(padding_len + 1, 0xff);
        padded_msg.extend_from_slice(msg);

        // now we overwrite it
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut padded_msg,
            )
            .unwrap();
        padded_msg.extend_from_slice(&nonce);
        assert_eq!(padded_msg.len(), target_len);
        padded_msg.into()
    }

    /// Decrypts a message.
    pub fn decrypt(&self, ctext: &[u8]) -> Result<Bytes, AeadError> {
        if ctext.len() < CHACHA20_POLY1305.nonce_len() + CHACHA20_POLY1305.tag_len() {
            return Err(AeadError::BadLength);
        }
        // nonce is last 12 bytes
        let (cytext, nonce) = ctext.split_at(ctext.len() - CHACHA20_POLY1305.nonce_len());
        // we now open
        let mut ctext = cytext.to_vec();
        self.key
            .open_in_place(
                Nonce::try_assume_unique_for_key(nonce).unwrap(),
                Aad::empty(),
                &mut ctext,
            )
            .ok()
            .ok_or(AeadError::DecryptionFailure)?;
        let truncate_to = ctext.len() - CHACHA20_POLY1305.tag_len();
        ctext.truncate(truncate_to);
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
            let mut msg = vec![0u8; rand::thread_rng().gen_range(0, 1400)];
            rand::thread_rng().fill_bytes(&mut msg);

            // Encrypt the test message
            let encrypted_msg = obfs_aead.encrypt(&msg);

            // Decrypt the encrypted message
            let decrypted_result = obfs_aead.decrypt(&encrypted_msg).unwrap();
            assert_eq!(&decrypted_result[..], &msg);
        }
    }
}
