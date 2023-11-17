use aead::Aead;
use aead::Payload;
use aes_gcm::AeadInPlace;
use aes_gcm::Aes128Gcm;
use aes_gcm::KeyInit;
use bytes::BufMut;
use bytes::BytesMut;

fn main() {
    let mut buf = BytesMut::new();
    buf.put(&b"123456"[..]);
    let key = b"1234567890123456";
    let nonce = b"123456789012";
    let cipher = Aes128Gcm::new_from_slice(key).unwrap();
    let plaintext = Payload { msg: &buf, aad: b"" };
    cipher.encrypt(nonce.into(), plaintext).unwrap();
    println!("{:?}", buf);
    cipher.encrypt_in_place(nonce.into(), b"", &mut buf).unwrap();
    println!("{:?}", buf);
    cipher.decrypt_in_place(nonce.into(), b"", &mut buf).expect("Invalid cipher text");
    println!("{:?}", buf);
}
