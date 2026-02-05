use byte_unit::Byte;
use bytes::Bytes;
use erasure::codecs::rs16::Rs16Chunk;
use erasure::utils::codec_trait::Chunk;
use glassbench::{glassbench, Bench};
use primitives::serde::{bincode_deserialize, bincode_serializer};
use std::mem;
use vec_commitment::committed_chunk::CommittedChunk;

use vec_commitment::txn_generator::RandomTxn;

glassbench!("data_bench", bench_iterator,);

// run cargo bench serde_for_chunks  >>>

fn bench_iterator(bench: &mut Bench) {
    let chunk_size = vec![0_usize, 100, 10000, 100000, 1000000, 100000000];
    let proof_size = 32 * 10;
    let proof = RandomTxn::generate_gibberish(proof_size);
    for cs in chunk_size.into_iter() {
        let data = RandomTxn::generate_gibberish(cs);
        let rs_chunk = Rs16Chunk::new(cs, data, cs);
        let committed_chunk = CommittedChunk::<Rs16Chunk>::new(cs, proof.clone(), rs_chunk.clone());

        let rs_bytes = bincode_serializer(&rs_chunk).expect("Successful serialization");
        let committed_bytes =
            bincode_serializer(&committed_chunk).expect("Successful serialization");

        let rs_size = mem::size_of_val(&rs_bytes);
        let committed_size = mem::size_of_val(&committed_bytes);

        let rs_mem = Byte::from_bytes(((rs_size * rs_bytes.len()) / rs_size) as u128)
            .get_appropriate_unit(false);
        let committed_mem =
            Byte::from_bytes(((committed_size * committed_bytes.len()) / committed_size) as u128)
                .get_appropriate_unit(false);

        let name = format!(
            "chunk_size{}_rs_mem_{}_committed_mem_{}",
            cs, rs_mem, committed_mem
        );
        bench_runner(
            bench,
            &name,
            rs_chunk,
            rs_bytes,
            committed_chunk,
            committed_bytes,
        );
    }
}

fn bench_runner(
    bench: &mut Bench,
    name: &str,
    rs_chunk: Rs16Chunk,
    rs_bytes: Bytes,
    committed_chunk: CommittedChunk<Rs16Chunk>,
    committed_bytes: Bytes,
) {
    let bench_name = format!("{}_rs_serializer", name,);
    bench.task(bench_name, |task| {
        task.iter(|| {
            bincode_serializer(&rs_chunk).expect("Successful serialization");
        });
    });

    let bench_name = format!("{}_committed_serializer", name,);
    bench.task(bench_name, |task| {
        task.iter(|| {
            bincode_serializer(&committed_chunk).expect("Successful serialization");
        });
    });

    let bench_name = format!("{}_rs_deserialize", name,);
    bench.task(bench_name, |task| {
        task.iter(|| {
            bincode_deserialize::<Rs16Chunk>(&rs_bytes).expect("Successful deserialize");
        });
    });

    let bench_name = format!("{}_committed_deserialize", name,);
    bench.task(bench_name, |task| {
        task.iter(|| {
            bincode_deserialize::<CommittedChunk<Rs16Chunk>>(&committed_bytes)
                .expect("Successful deserialize");
        });
    });
}
