#![no_main]
sp1_zkvm::entrypoint!(main);

use rsp_client_executor::{hash_transactions, io::SubblockInput, ClientExecutor, EthereumVariant};

pub fn main() {
    // Read the input.
    let input = sp1_zkvm::io::read_vec();
    let input = bincode::deserialize::<SubblockInput>(&input).unwrap();

    // This is never deserialized so I don't care about using slow bincode.
    // Also it's pretty small.
    let transaction_hash = hash_transactions(&input.current_block.body);
    // println!("yuwen_transaction_hash: {:?}", transaction_hash);
    sp1_zkvm::io::commit(&transaction_hash);

    // Execute the block.
    let executor = ClientExecutor;
    let state_diff =
        executor.execute_subblock::<EthereumVariant>(input).expect("failed to execute client");

    // println!("yuwen_subblock_output: {:?}", state_diff);

    // Commit the state diff.
    let serialized = rkyv::to_bytes::<rkyv::rancor::BoxedError>(&state_diff)
        .expect("failed to serialize state diff")
        .to_vec();
    // println!("yuwen_serialized: {:?}", serialized);
    sp1_zkvm::io::commit_slice(&serialized);
}
