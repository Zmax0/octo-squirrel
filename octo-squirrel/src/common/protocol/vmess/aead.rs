pub mod auth_id;
pub mod encrypt;
pub mod kdf;

pub struct AuthID;
pub struct Encrypt;
pub struct KDF;

#[cfg(test)]
mod test {
    use base64ct::Base64;
    use base64ct::Encoding;

    use super::AuthID;
    use super::KDF;
    use crate::common::protocol::vmess::now;

    #[test]
    fn test_kdf() {
        let bytes = KDF::kdf(b"Demo Key for Auth ID Test", Vec::new());
        assert_eq!("e50sLh+rC0B6LsALqzcblmfKNfZnQIbvOEJRgh9gBfg=", Base64::encode_string(&bytes));
    }

    #[test]
    fn test_kdf16() {
        let bytes = KDF::kdf16(b"Demo Key for Auth ID Test", vec![b"Demo Path for Auth ID Test"]);
        assert_eq!("ZuQa1H+nRfv9HpcyXpPb9A==", Base64::encode_string(&bytes));
    }

    #[test]
    fn test_kdfn() {
        let bytes: [u8; 33] = KDF::kdfn(b"Demo Key for Auth ID Test", vec![b"Demo Path for Auth ID Test"]);
        assert_eq!("ZuQa1H+nRfv9HpcyXpPb9KBNqsA+UP3zBS2nE2Zi3+EA", Base64::encode_string(&bytes));
    }

    #[test]
    fn test_matching() {
        let key = KDF::kdf16(b"Demo Key for Auth ID Test", vec![b"Demo Path for Auth ID Test"]);
        let auth_id = AuthID::create(&key, now());
        let mut keys = Vec::new();
        for i in 0..10000u32 {
            let key_i = KDF::kdf16(b"Demo Key for Auth ID Test2", vec![b"Demo Path for Auth ID Test", &i.to_be_bytes()]);
            keys.push(key_i);
        }
        assert!(!AuthID::matching(&auth_id, &keys));
        keys.push(key);
        assert!(AuthID::matching(&auth_id, &keys));
        let auth_id = AuthID::create(&key, now() + 1200);
        assert!(!AuthID::matching(&auth_id, &keys));
    }
}
