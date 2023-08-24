use sha2::{Digest, Sha256};

use super::KDF;

impl KDF {
    const MAX: usize = 32;

    pub fn kdf(key: &[u8], path: Vec<&[u8]>) -> [u8; Self::MAX] {
        let mut creator = HmacCreator { parent: None, value: b"VMess AEAD KDF" };
        for v in path {
            let parent = creator;
            creator = HmacCreator { parent: Some(Box::new(parent)), value: v }
        }
        let mut hmacf = creator.create();
        hmacf.update(key);
        hmacf.do_final()
    }

    pub fn kdfn<const N: usize>(key: &[u8], path: Vec<&[u8]>) -> [u8; N] {
        let mut out = [0; N];
        let len = N.min(Self::MAX);
        out[..len].copy_from_slice(&Self::kdf(key, path)[..len]);
        out
    }

    pub fn kdf16(key: &[u8], path: Vec<&[u8]>) -> [u8; 16] {
        Self::kdfn(key, path)
    }
}

struct HmacCreator<'a> {
    parent: Option<Box<HmacCreator<'a>>>,
    value: &'a [u8],
}

impl HmacCreator<'_> {
    fn create(&mut self) -> Box<dyn Hash> {
        return if let Some(parent) = self.parent.as_mut() {
            Box::new(Hmac::new(parent.create(), &self.value))
        } else {
            Box::new(Hmac::new(Sha256Wrapper(Sha256::new()).new(), &self.value))
        };
    }
}

#[derive(Clone)]
struct Sha256Wrapper(Sha256);

struct Hmac {
    inner: Box<dyn Hash>,
    outer: Box<dyn Hash>,
    ipad: [u8; 64],
    opad: [u8; 64],
}

impl Hmac {
    fn new(hash: Box<dyn Hash>, key: &[u8]) -> Self {
        let mut hm = Self { inner: hash.new(), outer: hash.new(), ipad: [0; 64], opad: [0; 64] };
        let key_len = key.len();
        if key_len > hm.inner.output_size() {
            hm.outer.update(key);
            return Hmac::new(hash, &hm.outer.do_final());
        }
        hm.ipad[0..key_len].copy_from_slice(key);
        hm.opad[0..key_len].copy_from_slice(key);
        for i in 0..hm.ipad.len() {
            hm.ipad[i] ^= 0x36;
        }
        for i in 0..hm.opad.len() {
            hm.opad[i] ^= 0x5c;
        }
        hm.inner.update(&hm.ipad);
        return hm;
    }
}

trait Hash {
    fn new(&self) -> Box<dyn Hash>;
    fn update(&mut self, data: &[u8]);
    fn do_final(&mut self) -> [u8; 32];
    fn output_size(&self) -> usize;
}

impl Hash for Sha256Wrapper {
    fn new(&self) -> Box<dyn Hash> {
        Box::new(self.clone())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    fn do_final(&mut self) -> [u8; 32] {
        self.0.finalize_reset().into()
    }

    fn output_size(&self) -> usize {
        32
    }
}

impl Hash for Hmac {
    fn new(&self) -> Box<dyn Hash> {
        Box::new(Self { inner: self.inner.new(), outer: self.outer.new(), ipad: self.ipad.clone(), opad: self.opad.clone() })
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
