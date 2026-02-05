use crate::utils::codec_trait::{Chunk, Codec, Setting};
use crate::utils::errors::FECError;
use primitives::serde::DeserializerCustom;
use primitives::Payload;
use reed_solomon_16::{ReedSolomonDecoder, ReedSolomonEncoder};
use serde::{Deserialize, Deserializer, Serialize};

pub const POSITION: usize = 64;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rs16Chunk {
    original_data_size: usize,
    index: usize,
    chunk: Vec<u8>,
    is_original_shard: bool,
}

impl Chunk for Rs16Chunk {
    fn new(index: usize, chunk: Vec<u8>, data_size: usize) -> Self {
        Self {
            original_data_size: data_size,
            index,
            chunk,
            is_original_shard: true,
        }
    }

    fn byte_chunk_ref(&self) -> &Vec<u8> {
        &self.chunk
    }

    fn get_chunk_index(&self) -> usize {
        self.index
    }
}

impl DeserializerCustom for Rs16Chunk {
    fn deserialize_wrapper<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <Rs16Chunk as Deserialize>::deserialize(deserializer)
    }
}

#[derive(Default, Clone, Debug)]
pub struct Rs16BufferItem {
    index: usize,
    chunk: Vec<u8>,
    is_original_shard: bool,
}

impl From<Rs16Chunk> for Rs16BufferItem {
    fn from(item: Rs16Chunk) -> Self {
        Self {
            index: item.index,
            chunk: item.chunk,
            is_original_shard: item.is_original_shard,
        }
    }
}

#[derive(Default, Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Rs16Settings {
    data_shards: usize,
    parity_shards: usize,
}

impl Setting for Rs16Settings {
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

impl Rs16Settings {
    pub fn calculate_max_shard_size(original_data_size: usize, data_shards: usize) -> usize {
        let mut max_shard_size = (original_data_size as f32 / data_shards as f32).ceil() as usize;
        if max_shard_size < POSITION {
            max_shard_size = POSITION;
        } else {
            max_shard_size += POSITION - (max_shard_size % POSITION);
        }
        max_shard_size
    }

    pub fn calculate_data_padding(
        original_data_size: usize,
        max_shard_size: usize,
        data_shards: usize,
    ) -> usize {
        (max_shard_size * data_shards) - original_data_size
    }
}

#[derive(Default, Debug, Clone)]
pub struct Rs16Codec {
    buffer: Vec<Rs16BufferItem>,
    original_data_size: usize,
}

impl Codec for Rs16Codec {
    type Setting = Rs16Settings;
    type Chunk = Rs16Chunk;

    fn encode(setting: Self::Setting, mut input: Payload) -> Result<Vec<Self::Chunk>, FECError> {
        let original_data_size = input.len();

        let max_shard_size =
            Self::Setting::calculate_max_shard_size(original_data_size, setting.data_shards);
        let pad = Self::Setting::calculate_data_padding(
            original_data_size,
            max_shard_size,
            setting.data_shards,
        );

        input.extend(std::iter::repeat(0).take(pad));

        let shards = input.chunks_mut(max_shard_size).collect::<Vec<&mut [u8]>>();

        let mut encoder =
            ReedSolomonEncoder::new(setting.data_shards, setting.parity_shards, max_shard_size)
                .map_err(|e| FECError::ConfigError(e.to_string()))?;

        for shard in &shards {
            encoder
                .add_original_shard(shard)
                .map_err(|e| FECError::ConfigError(e.to_string()))?;
        }

        let result = encoder
            .encode()
            .map_err(|e| FECError::FailedToEncode(e.to_string()))?;

        let recovery = result.recovery_iter();

        let mut original_res = shards
            .into_iter()
            .enumerate()
            .map(|(index, chunk)| Rs16Chunk {
                original_data_size,
                is_original_shard: true,
                index,
                chunk: chunk.to_owned(),
            })
            .collect::<Vec<Rs16Chunk>>();
        let recovery_res = recovery
            .into_iter()
            .enumerate()
            .map(|(index, chunk)| Rs16Chunk {
                original_data_size,
                is_original_shard: false,
                index: index + setting.data_shards,
                chunk: chunk.to_owned(),
            })
            .collect::<Vec<Rs16Chunk>>();
        original_res.extend(recovery_res);

        Ok(original_res)
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

        let max_shard_size =
            Rs16Settings::calculate_max_shard_size(self.original_data_size, setting.data_shards);

        let mut shards: Vec<&[u8]> = vec![];
        let tmp_shards: Vec<Vec<u8>> = vec![vec![]; setting.data_shards];
        tmp_shards.iter().for_each(|x| shards.push(x));

        let mut decoder =
            ReedSolomonDecoder::new(setting.data_shards, setting.parity_shards, max_shard_size)
                .map_err(|e| FECError::ConfigError(e.to_string()))?;

        for shard in self.buffer.iter() {
            if shard.is_original_shard {
                shards[shard.index] = &shard.chunk;

                decoder
                    .add_original_shard(shard.index, &shard.chunk)
                    .map_err(|e| FECError::ConfigError(e.to_string()))?;
            } else {
                decoder
                    .add_recovery_shard(shard.index - setting.data_shards, &shard.chunk)
                    .map_err(|e| FECError::ConfigError(e.to_string()))?;
            }
        }
        let result = decoder
            .decode()
            .map_err(|e| FECError::FailedToDecode(e.to_string()))?;

        result
            .restored_original_iter()
            .for_each(|(k, v)| shards[k] = v);

        let ans = shards
            .into_iter()
            .flatten()
            .take(self.original_data_size)
            .map(|x| x.to_owned())
            .collect::<Vec<u8>>();
        Ok(ans)
    }

    fn feed_len(&self) -> usize {
        self.buffer.len()
    }

    fn reset_decoder(&mut self) {
        self.buffer.clear()
    }
}

#[cfg(test)]
mod tests {
    use crate::codecs::rs16::{Rs16Chunk, Rs16Codec, Rs16Settings};
    use crate::utils::codec_trait::{Chunk, Codec, Setting};
    use rand::seq::SliceRandom;
    use rand::Rng;

    #[test]
    fn reed_solomon_galois_16_works() {
        let original_data = (0..1000)
            .map(|_| rand::thread_rng().gen::<u8>())
            .collect::<Vec<u8>>();
        let n = 10;
        let k = 5;

        let result = Rs16Codec::encode(Rs16Settings::new(n, k), original_data.clone());
        assert!(result.is_ok());

        // packet loss in transfer medium
        let mut received_packets = result.unwrap();
        let mut rng = rand::thread_rng();
        received_packets.shuffle(&mut rng);
        received_packets.truncate(n);

        // receiver side
        let mut decoder = Rs16Codec::default();
        let mut flag = false;
        for (idx, r) in received_packets.iter().enumerate() {
            decoder
                .feed(r.to_owned())
                .expect("Successful consumption of chunk");
            assert_eq!(decoder.feed_len(), idx + 1);
            let result = decoder.decode(Rs16Settings::new(n, k));
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
        let chunk = Rs16Chunk::new(5, data.clone(), 5000);
        assert_eq!(5, chunk.get_chunk_index());
        assert_eq!(&data, chunk.byte_chunk_ref());
        assert_eq!(5000, chunk.original_data_size);
        assert!(chunk.is_original_shard);
    }
}
