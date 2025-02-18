#![no_main]
sp1_zkvm::entrypoint!(main);

use rsp_client_executor::{hash_transactions, io::SubblockInput, ClientExecutor, EthereumVariant};

pub fn main() {
    // Read the input.
    let input_bytes = sp1_zkvm::io::read_vec();
    println!("len input bytes: {}", input_bytes.len());
    let input = bincode::deserialize::<SubblockInput>(&input_bytes).unwrap();

    println!("cycle-tracker-start: clone transactions");
    let transactions = input.current_block.body.clone();
    println!("cycle-tracker-end: clone transactions");

    // Execute the block.
    let executor = ClientExecutor;
    let state_diff =
        executor.execute_subblock::<EthereumVariant>(input).expect("failed to execute client");

    // Commit the state diff.
    println!("cycle-tracker-start: serialize state diff");
    let serialized = rkyv::to_bytes::<rkyv::rancor::BoxedError>(&state_diff)
        .expect("failed to serialize state diff")
        .to_vec();
    println!("cycle-tracker-end: serialize state diff");
    println!("cycle-tracker-start: commit");
    sp1_zkvm::io::commit(&(transactions, serialized));
    println!("cycle-tracker-end: commit");
}
