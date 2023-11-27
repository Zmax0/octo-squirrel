use aes::cipher::Unsigned;
use aes_gcm::aead::Aead;
use aes_gcm::aead::Buffer;
use aes_gcm::aead::Payload;
use aes_gcm::AeadCore;
use aes_gcm::AeadInPlace;
use aes_gcm::Aes128Gcm;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use chacha20poly1305::ChaCha20Poly1305;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CipherKind {
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

impl CipherKind {
    pub const VALUES: [CipherKind; 3] = [CipherKind::Aes128Gcm, CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305];

    pub fn to_aead_cipher(&self, key: &[u8]) -> Box<dyn CipherMethod> {
        match self {
            CipherKind::Aes128Gcm => Box::new(Aes128GcmCipher::new(&key)),
            CipherKind::Aes256Gcm => Box::new(Aes256GcmCipher::new(&key)),
            CipherKind::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305Cipher::new(&key)),
        }
    }
}

pub trait CipherMethod: Send {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8>;
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Vec<u8>;
    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut dyn Buffer);
    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut dyn Buffer);
    fn nonce_size(&self) -> usize;
    fn tag_size(&self) -> usize;
    fn ciphertext_overhead(&self) -> usize;
}

macro_rules! aead_impl {
    ($name:ident, $cipher:ty) => {
        pub struct $name {
            cipher: $cipher,
        }

        impl $name {
            pub const NONCE_SIZE: usize = <$cipher as AeadCore>::NonceSize::USIZE;
            pub const TAG_SIZE: usize = <$cipher as AeadCore>::TagSize::USIZE;
            pub const CIPHERTEXT_OVERHEAD: usize = <$cipher as AeadCore>::CiphertextOverhead::USIZE;

            pub fn new(key: &[u8]) -> Self {
                Self { cipher: <$cipher>::new_from_slice(key).unwrap() }
            }
        }

        impl CipherMethod for $name {
            fn encrypt(&self, nonce: &[u8], msg: &[u8], aad: &[u8]) -> Vec<u8> {
                self.cipher.encrypt(nonce.into(), Payload { msg, aad }).unwrap()
            }

            fn decrypt(&self, nonce: &[u8], msg: &[u8], aad: &[u8]) -> Vec<u8> {
                self.cipher.decrypt(nonce.into(), Payload { msg, aad }).expect("Invalid cipher text")
            }

            fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut dyn Buffer) {
                self.cipher.encrypt_in_place(nonce.into(), aad, buffer).unwrap()
            }

            fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut dyn Buffer) {
                self.cipher.decrypt_in_place(nonce.into(), aad, buffer).expect("Invalid cipher text")
            }

            fn nonce_size(&self) -> usize {
                $name::NONCE_SIZE
            }

            fn tag_size(&self) -> usize {
                $name::TAG_SIZE
            }

            fn ciphertext_overhead(&self) -> usize {
                $name::CIPHERTEXT_OVERHEAD
            }
        }
    };
}

aead_impl!(Aes128GcmCipher, Aes128Gcm);
aead_impl!(Aes256GcmCipher, Aes256Gcm);
aead_impl!(ChaCha20Poly1305Cipher, ChaCha20Poly1305);

#[cfg(test)]
mod test {
    use super::CipherKind;

    #[test]
    fn test_json_serialize() {
        let vec = vec![CipherKind::Aes128Gcm, CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305];
        let str = serde_json::to_string(&vec).unwrap();
        assert_eq!("[\"aes-128-gcm\",\"aes-256-gcm\",\"chacha20-poly1305\"]", str);
        let ciphers: Vec<CipherKind> = serde_json::from_str(str.as_str()).unwrap();
        assert_eq!(vec, ciphers);
    }
}
