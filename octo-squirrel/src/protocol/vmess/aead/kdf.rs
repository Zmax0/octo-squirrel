use digest::typenum::Unsigned;
use digest::OutputSizeUser;
use sha2::Digest;
use sha2::Sha256;

pub const SALT_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
pub const SALT_LENGTH_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
pub const SALT_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
pub const SALT_PAYLOAD_IV: &[u8] = b"VMess Header AEAD Nonce";
pub const SALT_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
pub const SALT_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
pub const SALT_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
pub const SALT_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const SIZE: usize = <Sha256 as OutputSizeUser>::OutputSize::USIZE;

pub fn kdf(key: &[u8], path: Vec<&[u8]>) -> [u8; SIZE] {
    let mut creator = HmacCreator { parent: None, value: b"VMess AEAD KDF" };
    for v in path {
        creator = HmacCreator { parent: Some(Box::new(creator)), value: v }
    }
    let mut hmacf = creator.create();
    hmacf.update(key);
    hmacf.do_final()
}

pub fn kdfn<const N: usize>(key: &[u8], path: Vec<&[u8]>) -> [u8; N] {
    let mut out = [0; N];
    let len = N.min(SIZE);
    out[..len].copy_from_slice(&kdf(key, path)[..len]);
    out
}

pub fn kdf16(key: &[u8], path: Vec<&[u8]>) -> [u8; 16] {
    kdfn(key, path)
}

struct Hmac {
    inner: Box<dyn Hash>,
    outer: Box<dyn Hash>,
    ipad: [u8; 64],
    opad: [u8; 64],
}

impl Hmac {
    fn new(hash: &dyn Hash, key: &[u8]) -> Self {
        let mut hm = Self { inner: hash.clone(), outer: hash.clone(), ipad: [0x36; 64], opad: [0x5c; 64] };
        for (i, k) in key.iter().enumerate() {
            hm.ipad[i] ^= k;
            hm.opad[i] ^= k;
        }
        hm.inner.update(&hm.ipad);
        hm
    }
}

trait Hash {
    fn clone(&self) -> Box<dyn Hash>;
    fn update(&mut self, data: &[u8]);
    fn do_final(&mut self) -> [u8; 32];
}

impl Hash for Sha256 {
    fn clone(&self) -> Box<dyn Hash> {
        Box::new(Clone::clone(self))
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(self, data)
    }

    fn do_final(&mut self) -> [u8; 32] {
        self.finalize_reset().into()
    }
}

impl Hash for Hmac {
    fn clone(&self) -> Box<dyn Hash> {
        Box::new(Self { inner: self.inner.clone(), outer: self.outer.clone(), ipad: self.ipad, opad: self.opad })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    fn do_final(&mut self) -> [u8; 32] {
        self.outer.update(&self.opad);
        self.outer.update(&self.inner.do_final());
        self.outer.do_final()
    }
}

struct HmacCreator<'a> {
    parent: Option<Box<HmacCreator<'a>>>,
    value: &'a [u8],
}

impl HmacCreator<'_> {
    fn create(&self) -> Box<dyn Hash> {
        if let Some(parent) = self.parent.as_ref() {
            Box::new(Hmac::new(parent.create().as_ref(), self.value))
        } else {
            Box::new(Hmac::new(&Sha256::new(), self.value))
        }
    }
}
