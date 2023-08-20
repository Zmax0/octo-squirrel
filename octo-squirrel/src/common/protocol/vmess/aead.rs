pub mod auth_id;
pub mod encrypt;
pub mod kdf;

pub struct AuthID;
pub struct Encrypt;
pub struct KDF;

#[cfg(test)]
mod test {
    use base64ct::{Base64, Encoding};

    use super::{AuthID, KDF};
    use crate::common::protocol::vmess;

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
        let authid = AuthID::create(&key, vmess::now());
        assert!(AuthID::matching(&authid, vec![&key]))
    }
}
