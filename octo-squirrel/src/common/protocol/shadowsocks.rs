#[derive(Copy, Clone)]
pub enum Mode {
    Client,
    Server,
}

impl Mode {
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Client => 0,
            Self::Server => 1,
        }
    }

    pub fn expect_u8(&self) -> u8 {
        match self {
            Self::Client => 1,
            Self::Server => 0,
        }
    }
}

pub mod aead {
    use md5::Digest;
    use md5::Md5;

    pub fn openssl_bytes_to_key<const N: usize>(password: &[u8]) -> [u8; N] {
        let mut encoded: [u8; N] = [0; N];
        let size = encoded.len();
        let mut hasher = Md5::new();
        hasher.update(password);
        let mut password_digest = hasher.finalize_reset();
        let mut container: Vec<u8> = vec![0; password.len() + password_digest.len()];
        let len = size.min(password_digest.len());
        encoded[..len].copy_from_slice(&password_digest);
        let mut index = password_digest.len();
        while index < size {
            let len = password_digest.len();
            container[..len].copy_from_slice(&password_digest);
            container[len..].copy_from_slice(password);
            hasher.update(&container);
            password_digest = hasher.finalize_reset();
            encoded[index..].copy_from_slice(&password_digest[..password_digest.len().min(size - index)]);
            index += password_digest.len();
        }
        encoded
    }

    #[cfg(test)]
    mod test {
        use base64ct::Encoding;

        use super::openssl_bytes_to_key;

        #[test]
        fn test_generate_key() {
            let password = b"Personal search-enabled assistant for programmers";
            let key: [u8; 16] = openssl_bytes_to_key(password);
            assert_eq!("zsWfM5hwvmTusK6sGOop5w==", base64ct::Base64::encode_string(&key));
            let key: [u8; 32] = openssl_bytes_to_key(password);
            assert_eq!("zsWfM5hwvmTusK6sGOop57hBNhUblVO/PpBKSm34Vu4=", base64ct::Base64::encode_string(&key));
        }
    }
}

pub mod aead_2022 {
    use base64ct::Base64;
    use base64ct::Encoding;

    pub fn password_to_keys<const N: usize>(password: &str) -> Result<([u8; N], Vec<[u8; N]>), base64ct::Error> {
        let split = password.split(':');
        let mut identity_keys = Vec::new();
        for s in split {
            let mut bytes = [0; N];
            Base64::decode(s, &mut bytes)?;
            identity_keys.push(bytes);
        }
        let enc_key = identity_keys.remove(identity_keys.len() - 1);
        Ok((enc_key, identity_keys))
    }
}
