#![no_main]
sp1_zkvm::entrypoint!(main);

use rsp_client_executor::{
    io::{read_aligned_vec, SubblockInput},
    ClientExecutor, EthereumVariant,
};
use rsp_mpt::EthereumState;

pub fn main() {
    // Read the input.
    println!("cycle-tracker-start: deserialize input");
    let input = sp1_zkvm::io::read::<SubblockInput>();
    println!("cycle-tracker-end: deserialize input");
    println!(
        "is_first_subblock: {:?}, is_last_subblock: {:?}",
        input.is_first_subblock, input.is_last_subblock
    );

    println!("cycle-tracker-start: deserialize rkyv stuff");

    let aligned = read_aligned_vec::<16>();
    let mut parent_state =
        rkyv::from_bytes::<EthereumState, rkyv::rancor::BoxedError>(&aligned).unwrap();

    println!("cycle-tracker-end: deserialize rkyv stuff");

    println!("cycle-tracker-start: clone transactions");
    let transactions = input.current_block.body.clone();
    println!("cycle-tracker-end: clone transactions");

    // Execute the block.
    let executor = ClientExecutor;
    let subblock_output = executor
        .execute_subblock::<EthereumVariant>(input, &mut parent_state)
        .expect("failed to execute client");

    // Commit the state diff.
    println!("cycle-tracker-start: serialize state diff");
    let serialized = bincode::serialize(&subblock_output).expect("failed to serialize state diff");
    println!("cycle-tracker-end: serialize state diff");
    println!("cycle-tracker-start: commit");
    sp1_zkvm::io::commit(&transactions);
    sp1_zkvm::io::commit_slice(&serialized);
    println!("cycle-tracker-end: commit");
}
