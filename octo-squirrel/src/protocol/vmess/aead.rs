pub mod auth_id;
pub mod encrypt;
pub mod kdf;

#[cfg(test)]
mod test {
    use base64ct::Base64;
    use base64ct::Encoding;

    use super::auth_id;
    use crate::protocol::vmess::aead::kdf;
    use crate::protocol::vmess::now;

    #[test]
    fn test_kdf() {
        let bytes = kdf::kdf(b"Demo Key for Auth ID Test", Vec::new());
        assert_eq!("e50sLh+rC0B6LsALqzcblmfKNfZnQIbvOEJRgh9gBfg=", Base64::encode_string(&bytes));
    }

    #[test]
    fn test_kdf16() {
        let bytes = kdf::kdf16(b"Demo Key for Auth ID Test", vec![b"Demo Path for Auth ID Test"]);
        assert_eq!("ZuQa1H+nRfv9HpcyXpPb9A==", Base64::encode_string(&bytes));
    }

    #[test]
    fn test_kdfn() {
        let bytes: [u8; 33] = kdf::kdfn(b"Demo Key for Auth ID Test", vec![b"Demo Path for Auth ID Test"]);
        assert_eq!("ZuQa1H+nRfv9HpcyXpPb9KBNqsA+UP3zBS2nE2Zi3+EA", Base64::encode_string(&bytes));
    }

    #[test]
    fn test_matching() -> anyhow::Result<()> {
        let key = kdf::kdf16(b"Demo Key for Auth ID Test", vec![b"Demo Path for Auth ID Test"]);
        let auth_id = auth_id::create(&key, now()?);
        let mut keys = Vec::new();
        for i in 0..10000u32 {
            let key_i = kdf::kdf16(b"Demo Key for Auth ID Test2", vec![b"Demo Path for Auth ID Test", &i.to_be_bytes()]);
            keys.push(key_i);
        }
        assert!(auth_id::matching(&auth_id, &keys)?.is_none());
        keys.push(key);
        assert!(auth_id::matching(&auth_id, &keys)?.is_some());
        let auth_id = auth_id::create(&key, now()? + 1200);
        assert!(auth_id::matching(&auth_id, &keys)?.is_none());
        Ok(())
    }
}
