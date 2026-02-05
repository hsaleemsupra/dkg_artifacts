use criterion::{black_box, criterion_group, criterion_main, Criterion};
use erasure::codecs::rs8::{Rs8Codec, Rs8Settings};
use erasure::utils::codec_trait::{Codec, Setting};
use vec_commitment::committed_chunk::CommittedChunk;
use deliver::codeword::Codeword;
use deliver::errors::DeliverError;
use socrypto::Hash;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("RS Coding");

    let nt = 52;
    let nc = 34;
    let fc = 15;
    let data_size = nt*(48+438);

    let mut data_vec: Vec<u8> = Vec::new();
    for _ in 0..data_size {
        data_vec.push(rand::random::<u8>()); // Replace 100 with the desired length
    }

    group.bench_with_input("Creating erasure chunks", &data_vec, |b, data_vec| {
        b.iter(|| {

            let chunks = Rs8Codec::encode(
                Rs8Settings::new(
                    (fc+1) as usize,
                    (nc - (fc+1)) as usize),
                data_vec.clone())
                .map_err(|e| DeliverError::GeneralError(format!("Failed to erasure encode data: {}", e.to_string()))).unwrap();

            let (root, committed_chunks) =
                CommittedChunk::commit_chunk_list(chunks)
                    .map_err(|e|
                        DeliverError::GeneralError(format!("Failed to create proofs for erasure coded data: {}", e.to_string()))).unwrap();

            black_box(root);
            black_box(committed_chunks);
        })
    });

    let chunks = Rs8Codec::encode(
        Rs8Settings::new(
            (fc+1) as usize,
            (nc - (fc+1)) as usize),
        data_vec.clone())
        .map_err(|e| DeliverError::GeneralError(format!("Failed to erasure encode data: {}", e.to_string()))).unwrap();

    let (root, committed_chunks) =
        CommittedChunk::commit_chunk_list(chunks)
            .map_err(|e|
                DeliverError::GeneralError(format!("Failed to create proofs for erasure coded data: {}", e.to_string()))).unwrap();


    group.bench_with_input("Verifying nc erasure chunks", &data_vec, |b, data_vec| {
        b.iter(|| {
            for chunk in &committed_chunks{
                let res = chunk
                    .verify(root.clone(), nc as usize)
                    .map_err(|e| DeliverError::GeneralError(format!("Failed to verify codeword: {}", e.to_string()))).unwrap();
                black_box(res);
            }
        })
    });


    group.bench_with_input("Reconstructing Data", &data_vec, |b, data_vec| {
        b.iter(|| {

            let mut decoder = Rs8Codec::default();
            for commited_chunk in committed_chunks.iter() {

                // Does not return an error
                decoder.feed(commited_chunk.clone().take_chunk()).unwrap();
            }

            let result = decoder.decode(Rs8Settings::new((fc+1) as usize,
                                                         (nc - (fc+1)) as usize));
            black_box(result);
        })
    });
}

criterion_group!(name = benches; config = Criterion::default().sample_size(15); targets = criterion_benchmark);
criterion_main!(benches);