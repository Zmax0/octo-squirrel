use digest::Digest;
use md5::Md5;

pub struct Auth;

impl Auth {
    pub fn generate_chacha20_poly1305_key(raw: &[u8]) -> [u8; 32] {
        let mut key = [0; 32];
        let mut hasher = Md5::new();
        hasher.update(raw);
        let res = hasher.finalize_reset();
        key[..16].copy_from_slice(&res[..]);
        hasher.update(&res[..16]);
        let res = hasher.finalize();
        key[16..].copy_from_slice(&res[..]);
        key
    }
}

#[test]
fn test_generate_chacha20_poly1305_key() {
    use base64ct::{Base64, Encoding};
    let data = b"fn bubble_sort<T: Ord>(arr: &mut [T]) {let mut swapped = true;while swapped {swapped = false;for i in 1..arr.len() {if arr[i - 1] > arr[i] {arr.swap(i - 1, i);swapped = true;}}}}";
    let res = Auth::generate_chacha20_poly1305_key(data);
    assert_eq!("UDKJ9PJ4zh6hDio6vuw0UhcSqk8njawoEziFz405238=", Base64::encode_string(&res));
}
