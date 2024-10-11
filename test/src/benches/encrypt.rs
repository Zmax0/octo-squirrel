use core::slice;

use anyhow::anyhow;
use bytes::BufMut;
use bytes::BytesMut;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use octo_squirrel::codec::aead::CipherKind;
use octo_squirrel::codec::aead::CipherMethod;
use rand::Rng;

fn by_chunk(key: &[u8], nonce: &[u8]) -> anyhow::Result<()> {
    let kind = CipherKind::Aes128Gcm;
    let cipher = CipherMethod::new(kind, &key);
    let mut dst = BytesMut::new();
    dst.reserve(18);
    let tag_size = cipher.tag_size();
    let encrypted_size_bytes = &mut dst.chunk_mut()[..2 + tag_size];
    let encrypted_size_bytes = unsafe { slice::from_raw_parts_mut(encrypted_size_bytes.as_mut_ptr(), encrypted_size_bytes.len()) };
    dst.put_u16(66 as u16);
    cipher.encrypt_in_place_detached(&nonce, &[], encrypted_size_bytes).map_err(|e| anyhow!(e))?;
    unsafe { dst.advance_mut(tag_size) };
    Ok(())
}

fn standard(key: &[u8], nonce: &[u8]) -> anyhow::Result<()> {
    let kind = CipherKind::Aes128Gcm;
    let cipher = CipherMethod::new(kind, &key);
    let mut dst: BytesMut = BytesMut::new();
    dst.put_u16(66);
    cipher.encrypt_in_place(&nonce, &[], &mut dst).map_err(|e| anyhow!(e))?;
    // println!("{:?}", &dst[..]);
    Ok(())
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut key = [0; 16];
    rand::thread_rng().fill(&mut key);
    let mut nonce = [0; 12];
    rand::thread_rng().fill(&mut nonce);
    c.bench_function("by chunk", |b| b.iter(|| by_chunk(&key, &nonce)));
    c.bench_function("standard", |b| b.iter(|| standard(&key, &nonce)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
