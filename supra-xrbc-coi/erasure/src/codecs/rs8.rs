use crate::utils::codec_trait::{Chunk, Codec, Setting};
use crate::utils::errors::FECError;
use primitives::serde::DeserializerCustom;
use primitives::Payload;
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rs8Chunk {
    original_data_size: usize,
    index: usize,
    chunk: Vec<u8>,
}

impl Chunk for Rs8Chunk {
    fn new(index: usize, chunk: Vec<u8>, data_size: usize) -> Self {
        Self {
            original_data_size: data_size,
            index,
            chunk,
        }
    }

    fn byte_chunk_ref(&self) -> &Vec<u8> {
        &self.chunk
    }

    fn get_chunk_index(&self) -> usize {
        self.index
    }
}

impl DeserializerCustom for Rs8Chunk {
    fn deserialize_wrapper<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <Rs8Chunk as Deserialize>::deserialize(deserializer)
    }
}

#[derive(Default, Clone, Debug)]
pub struct Rs8BufferItem {
    index: usize,
    chunk: Vec<u8>,
}

impl From<Rs8Chunk> for Rs8BufferItem {
    fn from(item: Rs8Chunk) -> Self {
        Self {
            index: item.index,
            chunk: item.chunk,
        }
    }
}

#[derive(Default, Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Rs8Settings {
    data_shards: usize,
    parity_shards: usize,
}

impl Setting for Rs8Settings {
    fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self {
            data_shards,
            parity_shards,
        }
    }

    fn data_shards(&self) -> usize {
        self.data_shards
    }

    fn parity_shards(&self) -> usize {
        self.parity_shards
    }
}

impl Rs8Settings {
    fn calculate_max_shard_size(
        original_data_size: usize,
        pad: usize,
        data_shards: usize,
    ) -> usize {
        (original_data_size + pad) / data_shards
    }

    fn calculate_data_padding(original_data_size: usize, data_shards: usize) -> usize {
        data_shards - (original_data_size % data_shards)
    }
}

#[derive(Clone, Default, Debug)]
pub struct Rs8Codec {
    buffer: Vec<Rs8BufferItem>,
    original_data_size: usize,
}

impl Codec for Rs8Codec {
    type Setting = Rs8Settings;
    type Chunk = Rs8Chunk;

    fn encode(setting: Self::Setting, mut input: Payload) -> Result<Vec<Self::Chunk>, FECError> {
        let original_data_size = input.len();

        let pad = Self::Setting::calculate_data_padding(original_data_size, setting.data_shards);
        let max_shard_size =
            Self::Setting::calculate_max_shard_size(original_data_size, pad, setting.data_shards);

        input.extend(std::iter::repeat(0).take(pad));

        let mut shards = input.chunks_mut(max_shard_size).collect::<Vec<&mut [u8]>>();

        let mut additional_shards: Vec<Vec<u8>> =
            vec![vec![0_u8; max_shard_size]; setting.parity_shards];

        additional_shards.iter_mut().for_each(|x| shards.push(x));

        let encoder = ReedSolomon::new(setting.data_shards, setting.parity_shards)
            .map_err(|e| FECError::ConfigError(e.to_string()))?;

        encoder
            .encode(&mut shards)
            .map_err(|e| FECError::FailedToEncode(e.to_string()))?;

        Ok(shards
            .into_iter()
            .enumerate()
            .map(|(index, chunk)| Rs8Chunk {
                original_data_size,
                index,
                chunk: chunk.to_owned(),
            })
            .collect::<Vec<Rs8Chunk>>())
    }

    fn feed(&mut self, item: Self::Chunk) -> Result<(), FECError> {
        if !self.buffer.len().gt(&0) {
            self.original_data_size = item.original_data_size;
        }
        self.buffer.push(item.into());
        Ok(())
    }

    fn decode(&mut self, setting: Self::Setting) -> Result<Payload, FECError> {
        if self.buffer.len().lt(&setting.data_shards) {
            return Err(FECError::NotEnoughData);
        }

        let mut shards = vec![None; setting.data_shards + setting.parity_shards()];

        let mut decoder_item = Vec::with_capacity(self.buffer.len());
        std::mem::swap(&mut decoder_item, &mut self.buffer);

        decoder_item
            .into_iter()
            .for_each(|item| shards[item.index] = Some(item.chunk));

        let decoder = ReedSolomon::new(setting.data_shards, setting.parity_shards)
            .map_err(|e| FECError::ConfigError(e.to_string()))?;
        decoder
            .reconstruct(&mut shards)
            .map_err(|e| FECError::FailedToDecode(e.to_string()))?;

        let shards = shards.into_iter().map(|x| x.unwrap());

        let padded_data = shards
            .into_iter()
            .take(setting.data_shards)
            .flatten()
            .take(self.original_data_size)
            .collect::<Vec<u8>>();
        Ok(padded_data)
    }

    fn feed_len(&self) -> usize {
        self.buffer.len()
    }

    fn reset_decoder(&mut self) {
        self.buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use crate::codecs::rs8::{Rs8Chunk, Rs8Codec, Rs8Settings};
    use crate::utils::codec_trait::{Chunk, Codec, Setting};
    use rand::seq::SliceRandom;
    use rand::Rng;

    #[test]
    fn reed_solomon_galois_8_works() {
        let original_data = (0..1000)
            .map(|_| rand::thread_rng().gen::<u8>())
            .collect::<Vec<u8>>();
        let n = 10;
        let k = 5;

        let result = Rs8Codec::encode(Rs8Settings::new(n, k), original_data.clone());
        assert!(result.is_ok());

        // packet loss in transfer medium
        let mut received_packets = result.unwrap();
        let mut rng = rand::thread_rng();
        received_packets.shuffle(&mut rng);
        received_packets.truncate(n);

        // receiver side
        let mut decoder = Rs8Codec::default();
        let mut flag = false;
        for (idx, r) in received_packets.iter().enumerate() {
            decoder
                .feed(r.to_owned())
                .expect("Successful consumption of chunks");
            assert_eq!(decoder.feed_len(), idx + 1);
            let result = decoder.decode(Rs8Settings::new(n, k));
            if result.is_ok() {
                assert_eq!(original_data, result.unwrap());
                println!("x");
                flag = true;
                break;
            } else {
                print!(".");
            }
        }
        assert!(flag);
    }

    #[test]
    fn check_new_ifc() {
        let data = vec![5; 1000];
        let chunk = Rs8Chunk::new(5, data.clone(), 5000);
        assert_eq!(5, chunk.get_chunk_index());
        assert_eq!(&data, chunk.byte_chunk_ref());
        assert_eq!(5000, chunk.original_data_size);
    }
}
