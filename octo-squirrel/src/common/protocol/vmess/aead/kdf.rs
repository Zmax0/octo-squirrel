use digest::typenum::Unsigned;
use digest::OutputSizeUser;
use sha2::Digest;
use sha2::Sha256;

use super::KDF;

impl KDF {
    pub const SALT_LENGTH_KEY: &'static [u8] = b"VMess Header AEAD Key_Length";
    pub const SALT_LENGTH_IV: &'static [u8] = b"VMess Header AEAD Nonce_Length";
    pub const SALT_PAYLOAD_KEY: &'static [u8] = b"VMess Header AEAD Key";
    pub const SALT_PAYLOAD_IV: &'static [u8] = b"VMess Header AEAD Nonce";
    pub const SALT_AEAD_RESP_HEADER_LEN_KEY: &'static [u8] = b"AEAD Resp Header Len Key";
    pub const SALT_AEAD_RESP_HEADER_LEN_IV: &'static [u8] = b"AEAD Resp Header Len IV";
    pub const SALT_AEAD_RESP_HEADER_PAYLOAD_KEY: &'static [u8] = b"AEAD Resp Header Key";
    pub const SALT_AEAD_RESP_HEADER_PAYLOAD_IV: &'static [u8] = b"AEAD Resp Header IV";
    const SIZE: usize = <Sha256 as OutputSizeUser>::OutputSize::USIZE;

    pub fn kdf(key: &[u8], path: Vec<&[u8]>) -> [u8; Self::SIZE] {
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
        let len = N.min(Self::SIZE);
        out[..len].copy_from_slice(&Self::kdf(key, path)[..len]);
        out
    }

    pub fn kdf16(key: &[u8], path: Vec<&[u8]>) -> [u8; 16] {
        Self::kdfn(key, path)
    }
}

struct Hmac {
    inner: Box<dyn Hash>,
    outer: Box<dyn Hash>,
    ipad: [u8; 64],
    opad: [u8; 64],
}

impl Hmac {
    fn new(hash: Box<dyn Hash>, key: &[u8]) -> Self {
        let key_len = key.len();
        if key_len > hash.output_size() {
            let mut outer = hash.init();
            outer.update(key);
            return Hmac::new(hash, &outer.do_final());
        }
        let mut hm = Self { inner: hash.init(), outer: hash.init(), ipad: [0; 64], opad: [0; 64] };
        hm.ipad[0..key_len].copy_from_slice(key);
        hm.opad[0..key_len].copy_from_slice(key);

        hm.ipad.iter_mut().for_each(|x| *x ^= 0x36);
        hm.opad.iter_mut().for_each(|x| *x ^= 0x5c);
        hm.inner.update(&hm.ipad);
        hm
    }
}

trait Hash {
    fn init(&self) -> Box<dyn Hash>;
    fn update(&mut self, data: &[u8]);
    fn do_final(&mut self) -> [u8; 32];
    fn output_size(&self) -> usize;
}

type BoxSha256 = Box<Sha256>;

impl Hash for BoxSha256 {
    fn init(&self) -> Box<dyn Hash> {
        Box::new(self.clone())
    }

    fn update(&mut self, data: &[u8]) {
        Sha256::update(self, data)
    }

    fn do_final(&mut self) -> [u8; 32] {
        self.finalize_reset().into()
    }

    fn output_size(&self) -> usize {
        <Sha256 as OutputSizeUser>::OutputSize::USIZE
    }
}

impl Hash for Hmac {
    fn init(&self) -> Box<dyn Hash> {
        Box::new(Self { inner: self.inner.init(), outer: self.outer.init(), ipad: self.ipad, opad: self.opad })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }

    fn do_final(&mut self) -> [u8; 32] {
        self.outer.update(&self.opad);
        self.outer.update(&self.inner.do_final());
        self.outer.do_final()
    }

    fn output_size(&self) -> usize {
        self.inner.output_size()
    }
}

struct HmacCreator<'a> {
    parent: Option<Box<HmacCreator<'a>>>,
    value: &'a [u8],
}

impl HmacCreator<'_> {
    fn create(&mut self) -> Box<dyn Hash> {
        return if let Some(parent) = self.parent.as_mut() {
            Box::new(Hmac::new(parent.create(), self.value))
        } else {
            Box::new(Hmac::new(Box::new(Box::new(Sha256::new())), self.value))
        };
    }
}
