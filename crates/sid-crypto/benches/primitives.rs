// SPDX-License-Identifier: AGPL-3.0-only
//! Criterion benchmarks for CryptoPrimitives backends.
//!
//! Side-by-side comparison: RustCrypto vs aws-lc-rs (BoringSSL).
//! Measures: AES-256-GCM encrypt/decrypt, HMAC-SHA256, HKDF-SHA256, SHA-256, random_bytes.
//! Payload sizes: 64B, 1KB, 4KB, 64KB for AEAD operations.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use sid_keys::{CryptoPrimitives, RustCryptoPrimitives};

#[cfg(feature = "aws-lc")]
use sid_crypto::AwsLcPrimitives;

// ── AES-256-GCM encrypt ──

fn bench_aes_gcm_encrypt(c: &mut Criterion) {
    let rc = RustCryptoPrimitives::new();
    let key = [42u8; 32];
    let aad = b"bench:context";

    let mut group = c.benchmark_group("aes_256_gcm_encrypt");
    for size in [64, 1024, 4096, 65536] {
        let plaintext = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("rustcrypto", size), &size, |b, _| {
            b.iter(|| {
                let nonce = rc.random_nonce();
                rc.aes_256_gcm_encrypt(&key, &nonce, &plaintext, aad)
                    .unwrap()
            })
        });

        #[cfg(feature = "aws-lc")]
        {
            let alc = AwsLcPrimitives;
            group.bench_with_input(BenchmarkId::new("aws-lc", size), &size, |b, _| {
                b.iter(|| {
                    let nonce = alc.random_nonce();
                    alc.aes_256_gcm_encrypt(&key, &nonce, &plaintext, aad)
                        .unwrap()
                })
            });
        }
    }
    group.finish();
}

// ── AES-256-GCM decrypt ──

fn bench_aes_gcm_decrypt(c: &mut Criterion) {
    let rc = RustCryptoPrimitives::new();
    let key = [42u8; 32];
    let aad = b"bench:context";

    let mut group = c.benchmark_group("aes_256_gcm_decrypt");
    for size in [64, 1024, 4096, 65536] {
        let plaintext = vec![0xABu8; size];
        let nonce = rc.random_nonce();
        let ciphertext = rc
            .aes_256_gcm_encrypt(&key, &nonce, &plaintext, aad)
            .unwrap();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("rustcrypto", size), &size, |b, _| {
            b.iter(|| {
                rc.aes_256_gcm_decrypt(&key, &nonce, &ciphertext, aad)
                    .unwrap()
            })
        });

        #[cfg(feature = "aws-lc")]
        {
            let alc = AwsLcPrimitives;
            group.bench_with_input(BenchmarkId::new("aws-lc", size), &size, |b, _| {
                b.iter(|| {
                    alc.aes_256_gcm_decrypt(&key, &nonce, &ciphertext, aad)
                        .unwrap()
                })
            });
        }
    }
    group.finish();
}

// ── HMAC-SHA256 ──

fn bench_hmac_sha256(c: &mut Criterion) {
    let rc = RustCryptoPrimitives::new();
    let key = [99u8; 32];
    let data = vec![0xCDu8; 1024];

    let mut group = c.benchmark_group("hmac_sha256");
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("rustcrypto", |b| b.iter(|| rc.hmac_sha256(&key, &data)));

    #[cfg(feature = "aws-lc")]
    {
        let alc = AwsLcPrimitives;
        group.bench_function("aws-lc", |b| b.iter(|| alc.hmac_sha256(&key, &data)));
    }

    group.finish();
}

// ── HKDF-SHA256 ──

fn bench_hkdf_sha256(c: &mut Criterion) {
    let rc = RustCryptoPrimitives::new();
    let ikm = [0x0Bu8; 32];
    let salt = [0x01u8; 16];
    let info = b"bench:derive";

    let mut group = c.benchmark_group("hkdf_sha256");

    group.bench_function("rustcrypto", |b| {
        b.iter(|| rc.hkdf_sha256(&ikm, &salt, info, 32).unwrap())
    });

    #[cfg(feature = "aws-lc")]
    {
        let alc = AwsLcPrimitives;
        group.bench_function("aws-lc", |b| {
            b.iter(|| alc.hkdf_sha256(&ikm, &salt, info, 32).unwrap())
        });
    }

    group.finish();
}

// ── SHA-256 ──

fn bench_sha256(c: &mut Criterion) {
    let rc = RustCryptoPrimitives::new();
    let data = vec![0xEFu8; 1024];

    let mut group = c.benchmark_group("sha256");
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("rustcrypto", |b| b.iter(|| rc.sha256(&data)));

    #[cfg(feature = "aws-lc")]
    {
        let alc = AwsLcPrimitives;
        group.bench_function("aws-lc", |b| b.iter(|| alc.sha256(&data)));
    }

    group.finish();
}

// ── random_bytes ──

fn bench_random_bytes(c: &mut Criterion) {
    let rc = RustCryptoPrimitives::new();

    let mut group = c.benchmark_group("random_bytes");

    group.bench_function("rustcrypto", |b| {
        b.iter(|| {
            let mut buf = [0u8; 32];
            rc.random_bytes(&mut buf);
            buf
        })
    });

    #[cfg(feature = "aws-lc")]
    {
        let alc = AwsLcPrimitives;
        group.bench_function("aws-lc", |b| {
            b.iter(|| {
                let mut buf = [0u8; 32];
                alc.random_bytes(&mut buf);
                buf
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_aes_gcm_encrypt,
    bench_aes_gcm_decrypt,
    bench_hmac_sha256,
    bench_hkdf_sha256,
    bench_sha256,
    bench_random_bytes,
);
criterion_main!(benches);
