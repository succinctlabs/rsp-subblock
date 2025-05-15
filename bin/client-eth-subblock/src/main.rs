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

    println!("cycle-tracker-start: commit input");
    sp1_zkvm::io::commit(&input);
    println!("cycle-tracker-end: commit input");

    println!("cycle-tracker-start: deserialize rkyv stuff");

    let aligned = read_aligned_vec::<16>();
    let mut parent_state =
        rkyv::from_bytes::<EthereumState, rkyv::rancor::BoxedError>(&aligned).unwrap();

    println!("cycle-tracker-end: deserialize rkyv stuff");

    println!("cycle-tracker-start: execute subblock");
    // Execute the block.
    let executor = ClientExecutor;
    let subblock_output = executor
        .execute_subblock::<EthereumVariant>(input, &mut parent_state)
        .expect("failed to execute client");
    println!("cycle-tracker-end: execute subblock");

    // Commit the state diff.
    sp1_zkvm::io::commit(&subblock_output);
}
