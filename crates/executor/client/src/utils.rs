use reth_primitives::{Transaction, TransactionSigned};
use sha2::{Digest, Sha256};

macro_rules! profile {
    ($name:expr, $block:block) => {{
        #[cfg(target_os = "zkvm")]
        {
            println!("cycle-tracker-start: {}", $name);
            let result = (|| $block)();
            println!("cycle-tracker-end: {}", $name);
            result
        }

        #[cfg(not(target_os = "zkvm"))]
        {
            $block
        }
    }};
}

/// Hashes a bunch of transactions into a 32 byte hash.
pub fn hash_transactions(transactions: &[TransactionSigned]) -> [u8; 32] {
    let serialized_transactions = bincode::serialize(transactions).unwrap();
    let transaction_hash = Sha256::digest(&serialized_transactions);
    transaction_hash.into()
}
