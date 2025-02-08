use aes::cipher::block_padding::NoPadding;
use aes::cipher::BlockDecryptMut;
use aes::cipher::BlockEncryptMut;
use aes::Aes128;
use aes::Aes256;
use aes_gcm::aead::KeyInit;
use aes_gcm::aead::KeySizeUser;
use ecb::Decryptor;
use ecb::Encryptor;

macro_rules! aes_ecb_no_padding_impl {
    ($name:ident, $aes:ident) => {
        pub struct $name;
        impl $name {
            pub fn encrypt(key: &[u8], buf: &mut [u8], len: usize) {
                type EcbEnc = Encryptor<$aes>;
                EcbEnc::new_from_slice(&key[..<$aes as KeySizeUser>::key_size()])
                    .expect("Invalid length")
                    .encrypt_padded_mut::<NoPadding>(buf, len)
                    .expect("Encrypt error");
            }

            pub fn decrypt(key: &[u8], buf: &mut [u8]) {
                type EcbDec = Decryptor<$aes>;
                EcbDec::new_from_slice(&key[..<$aes as KeySizeUser>::key_size()])
                    .expect("Invalid length")
                    .decrypt_padded_mut::<NoPadding>(buf)
                    .expect("Decrypt error");
            }
        }
    };
}

aes_ecb_no_padding_impl!(Aes128EcbNoPadding, Aes128);
aes_ecb_no_padding_impl!(Aes256EcbNoPadding, Aes256);

#[cfg(test)]
mod test {
    use base64ct::Base64;
    use base64ct::Encoding;

    use super::Aes128EcbNoPadding;
    use crate::crypto::Aes256EcbNoPadding;

    #[test]
    fn test_aes_128() {
        let key = b"4ylXkB2KedlvbLFytehZISl HZNo3s3L";
        let mut buf = Base64::decode_vec("P1RKHzOxcv1GKRlbD5OZGA==").unwrap();
        Aes128EcbNoPadding::decrypt(key, &mut buf);
        assert_eq!("VqaYmC3G66ZuPB6J", String::from_utf8(buf).unwrap())
    }

    #[test]
    fn test_aes_256() {
        let key = b"4ylXkB2KedlvbLFytehZISl HZNo3s3LR049qziLBO9YVsZB";
        let mut buf = Base64::decode_vec("P1RKHzOxcv1GKRlbD5OZGA==").unwrap();
        Aes256EcbNoPadding::decrypt(key, &mut buf);
        assert_eq!("Tp5MsnjQk/37dPkQpaBB9w==", Base64::encode_string(&buf))
    }
}
