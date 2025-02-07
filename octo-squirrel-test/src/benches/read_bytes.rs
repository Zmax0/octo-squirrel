use core::slice;
use std::io::Cursor;

use bytes::Buf;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use rand::Rng;

fn by_raw_ptr(bytes: &mut [u8]) -> anyhow::Result<(u64, u64)> {
    let mut rng = rand::rng();
    let index = rng.random_range(0..1016);
    let a = {
        let a = &bytes[index..];
        let a: &[u64] = unsafe { slice::from_raw_parts(a.as_ptr() as *const _, 1) };
        u64::from_be(a[0])
    };
    let index = rng.random_range(0..1016);
    let b = {
        let b = &bytes[index..];
        let b: &[u64] = unsafe { slice::from_raw_parts(b.as_ptr() as *const _, 1) };
        u64::from_be(b[0])
    };
    Ok((a, b))
}

fn standard(bytes: &mut [u8]) -> anyhow::Result<(u64, u64)> {
    let mut cursor = Cursor::new(bytes);
    let mut rng = rand::rng();
    let index = rng.random_range(0..1016);
    cursor.set_position(index);
    let a = cursor.get_u64();
    let index = rng.random_range(0..1016);
    cursor.set_position(index);
    let b = cursor.get_u64();
    Ok((a, b))
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut bytes = [0; 1024];
    rand::rng().fill(&mut bytes);
    let mut group: criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> = c.benchmark_group("read_bytes");
    group.bench_function("raw_ptr", |b| b.iter(|| by_raw_ptr(&mut bytes)));
    group.bench_function("std", |b| b.iter(|| standard(&mut bytes)));
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
