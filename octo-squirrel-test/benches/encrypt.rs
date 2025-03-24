use core::slice;

use anyhow::anyhow;
use bytes::BufMut;
use bytes::BytesMut;
use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use octo_squirrel::codec::aead::CipherKind;
use octo_squirrel::codec::aead::CipherMethod;
use rand::Rng;

fn by_chunk(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> anyhow::Result<()> {
    let kind = CipherKind::Aes128Gcm;
    let cipher = CipherMethod::new(kind, &key);
    let tag_size = cipher.tag_size();
    let cipher_text_len = plaintext.len() + tag_size;
    let mut dst = BytesMut::new();
    dst.reserve(cipher_text_len);
    let encrypted_size_bytes = &mut dst.chunk_mut()[..cipher_text_len];
    let encrypted_size_bytes = unsafe { slice::from_raw_parts_mut(encrypted_size_bytes.as_mut_ptr(), encrypted_size_bytes.len()) };
    dst.extend_from_slice(plaintext);
    cipher.encrypt_in_place_detached(&nonce, &[], encrypted_size_bytes).map_err(|e| anyhow!(e))?;
    unsafe { dst.advance_mut(tag_size) };
    Ok(())
}

fn standard(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> anyhow::Result<()> {
    let kind = CipherKind::Aes128Gcm;
    let cipher = CipherMethod::new(kind, &key);
    let mut dst: BytesMut = BytesMut::new();
    dst.extend_from_slice(plaintext);
    cipher.encrypt_in_place(&nonce, &[], &mut dst).map_err(|e| anyhow!(e))?;
    Ok(())
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::rng();
    let mut key = [0; 16];
    rng.fill(&mut key);
    let mut nonce = [0; 12];
    rng.fill(&mut nonce);
    let mut plaintext = [0; 1024];
    rng.fill(&mut plaintext);
    let mut group = c.benchmark_group("encrypt");
    group.bench_function("chunk", |b| b.iter(|| by_chunk(&key, &nonce, &plaintext)));
    group.bench_function("std", |b| b.iter(|| standard(&key, &nonce, &plaintext)));
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
