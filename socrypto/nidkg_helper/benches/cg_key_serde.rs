use criterion::{criterion_group, criterion_main, Criterion};
use nidkg_helper::cgdkg::{CGPublicKey, CGSecretKey};
use rayon::prelude::*;

fn cg_public_key_deserialize_sequential(raw_pks: &[Vec<u8>]) {
    raw_pks.iter().for_each(|pk| {
        bincode::deserialize::<CGPublicKey>(pk).expect("Successful deserialization");
    });
}

fn cg_public_key_deserialize_parallel(raw_pks: &Vec<Vec<u8>>) {
    raw_pks.par_iter().for_each(|pk| {
        bincode::deserialize::<CGPublicKey>(pk).expect("Successful deserialization");
    });
}

fn cg_public_key_serialize_sequential(psk: &[CGPublicKey]) -> Vec<Vec<u8>> {
    psk.iter()
        .map(|pk| bincode::serialize(pk).expect("Successful serialization"))
        .collect()
}
fn cg_public_key_serialize_parallel(psk: &[CGPublicKey]) -> Vec<Vec<u8>> {
    psk.par_iter()
        .map(|pk| bincode::serialize(pk).expect("Successful serialization"))
        .collect()
}

fn generate_pks(count: usize) -> (Vec<Vec<u8>>, Vec<CGPublicKey>) {
    (0..count)
        .into_par_iter()
        .map(|_| CGSecretKey::generate())
        .map(|sk| CGPublicKey::try_from(&sk).expect("Successful PK Creation"))
        .map(|pk| {
            (
                bincode::serialize(&pk).expect("Successful serialization"),
                pk,
            )
        })
        .unzip()
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("CG Public Key");
    let (raw_pks, pks) = generate_pks(70);
    group.bench_with_input("Sequential Serialize", &pks, |b, pks| {
        b.iter(|| cg_public_key_serialize_sequential(pks))
    });
    group.bench_with_input("Parallel Serialize", &pks, |b, pks| {
        b.iter(|| cg_public_key_serialize_parallel(pks))
    });
    group.bench_with_input("Sequential deserialize", &raw_pks, |b, raw_pks| {
        b.iter(|| cg_public_key_deserialize_sequential(raw_pks))
    });
    group.bench_with_input("Parallel deserialize", &raw_pks, |b, raw_pks| {
        b.iter(|| cg_public_key_deserialize_parallel(raw_pks))
    });
}

criterion_group!(name = benches; config = Criterion::default().sample_size(15); targets = criterion_benchmark);
criterion_main!(benches);
