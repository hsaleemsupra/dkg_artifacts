use ed25519_dalek::Keypair;
use rand::rngs::StdRng;
use rand::{thread_rng, Rng, SeedableRng};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

const MAX_TXN_SIZE: usize = 512;

pub enum GeneratorType {
    Gibberish,
    KeyValuePair,
}

impl GeneratorType {
    pub fn spawn_the_generator(&self, batch_size: usize, transaction_size: usize) -> Vec<Vec<u8>> {
        let vec1 = vec![0; batch_size];
        match self {
            GeneratorType::Gibberish => vec1
                .par_iter()
                .map(|_| RandomTxn::new(transaction_size).take())
                .collect::<Vec<Vec<u8>>>(),
            GeneratorType::KeyValuePair => vec1
                .par_iter()
                .map(|_| Account::new().take())
                .collect::<Vec<Vec<u8>>>(),
        }
    }
}

struct Account {
    keypair: Vec<u8>,
}

impl Default for Account {
    fn default() -> Self {
        let mut cs_prng: StdRng = SeedableRng::from_entropy();
        let keypair = Keypair::generate(&mut cs_prng).to_bytes().to_vec();
        Self { keypair }
    }
}

impl Account {
    fn new() -> Self {
        Account::default()
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.keypair)
    }
}

pub struct RandomTxn {
    txn: Vec<u8>,
}

impl Default for RandomTxn {
    fn default() -> Self {
        Self {
            txn: RandomTxn::generate_gibberish(MAX_TXN_SIZE),
        }
    }
}

impl RandomTxn {
    pub fn generate_gibberish(txn_size: usize) -> Vec<u8> {
        (0..txn_size).map(|_| thread_rng().gen::<u8>()).collect()
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.txn)
    }

    fn new(transaction_size: usize) -> Self {
        Self {
            txn: RandomTxn::generate_gibberish(transaction_size),
        }
    }
}
