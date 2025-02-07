#![no_main]
sp1_zkvm::entrypoint!(main);

use rsp_client_executor::{
    io::{SubblockInput, SubblockOutput},
    ClientExecutor, EthereumVariant,
};

use sha2::{Digest, Sha256};
pub fn main() {
    // Read the input.
    let input = sp1_zkvm::io::read_vec();
    let input = bincode::deserialize::<SubblockInput>(&input).unwrap();

    // This is never deserialized so I don't care about using slow bincode.
    // Also it's pretty small.
    let serialized_transactions = bincode::serialize(&input.current_block.body).unwrap();
    let transaction_hash = Sha256::digest(&serialized_transactions);
    sp1_zkvm::io::commit(&transaction_hash.as_slice());

    // Execute the block.
    let executor = ClientExecutor;
    let state_diff =
        executor.execute_subblock::<EthereumVariant>(input).expect("failed to execute client");

    // Commit the state diff.
    let serialized = rkyv::to_bytes::<rkyv::rancor::BoxedError>(&state_diff)
        .expect("failed to serialize state diff")
        .to_vec();
    sp1_zkvm::io::commit_slice(&serialized);
}
