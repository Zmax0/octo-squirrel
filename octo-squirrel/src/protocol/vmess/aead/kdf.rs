use digest::OutputSizeUser;
use digest::typenum::Unsigned;
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
    let mut hmac = creator.create();
    hmac.update(key);
    hmac.do_final()
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

#[derive(Clone)]
struct Hmac {
    inner: Box<Hash>,
    outer: Box<Hash>,
    ipad: [u8; 64],
    opad: [u8; 64],
}

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

impl Hmac {
    fn new(key: &[u8]) -> Self {
        let mut hm = Self {
            inner: Box::new(Hash::Sha256(Sha256::default())),
            outer: Box::new(Hash::Sha256(Sha256::default())),
            ipad: [IPAD; 64],
            opad: [OPAD; 64],
        };
        hm.init(key);
        hm
    }

    fn from_hmac(parent: Hmac, key: &[u8]) -> Self {
        let mut hm = Self { inner: Box::new(Hash::Hmac(parent.clone())), outer: Box::new(Hash::Hmac(parent)), ipad: [IPAD; 64], opad: [OPAD; 64] };
        hm.init(key);
        hm
    }

    fn init(&mut self, key: &[u8]) {
        for (i, k) in key.iter().enumerate() {
            self.ipad[i] ^= k;
            self.opad[i] ^= k;
        }
        self.inner.update(&self.ipad);
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

#[derive(Clone)]
enum Hash {
    Sha256(Sha256),
    Hmac(Hmac),
}

impl Hash {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => Digest::update(h, data),
            Self::Hmac(h) => h.update(data),
        }
    }

    fn do_final(&mut self) -> [u8; 32] {
        match self {
            Self::Sha256(h) => h.finalize_reset().into(),
            Self::Hmac(h) => h.do_final(),
        }
    }
}

struct HmacCreator<'a> {
    parent: Option<Box<HmacCreator<'a>>>,
    value: &'a [u8],
}

impl HmacCreator<'_> {
    fn create(&self) -> Hmac {
        if let Some(parent) = self.parent.as_ref() { Hmac::from_hmac(parent.create(), self.value) } else { Hmac::new(self.value) }
    }
}
