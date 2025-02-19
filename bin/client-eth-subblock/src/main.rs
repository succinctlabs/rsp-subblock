#![no_main]
sp1_zkvm::entrypoint!(main);

use reth_trie::HashedPostState;
use rkyv::util::AlignedVec;
use rsp_client_executor::{io::SubblockInput, ClientExecutor, EthereumVariant};
use rsp_mpt::EthereumState;

pub fn main() {
    // Read the input.
    println!("cycle-tracker-start: deserialize input");
    let input = sp1_zkvm::io::read::<SubblockInput>();
    println!("cycle-tracker-end: deserialize input");

    let parent_state_bytes = sp1_zkvm::io::read_vec();
    let input_state_diff_bytes = sp1_zkvm::io::read_vec();

    println!("cycle-tracker-start: deserialize rkyv stuff");

    let mut aligned = AlignedVec::<16>::with_capacity(parent_state_bytes.len());
    aligned.extend_from_slice(&parent_state_bytes);
    let parent_state =
        rkyv::from_bytes::<EthereumState, rkyv::rancor::BoxedError>(&aligned).unwrap();

    let mut aligned = AlignedVec::<16>::with_capacity(input_state_diff_bytes.len());
    aligned.extend_from_slice(&input_state_diff_bytes);
    let input_state_diff =
        rkyv::from_bytes::<HashedPostState, rkyv::rancor::BoxedError>(&aligned).unwrap();
    println!("cycle-tracker-end: deserialize rkyv stuff");

    println!("cycle-tracker-start: clone transactions");
    let transactions = input.current_block.body.clone();
    println!("cycle-tracker-end: clone transactions");

    // Execute the block.
    let executor = ClientExecutor;
    let state_diff = executor
        .execute_subblock::<EthereumVariant>(input, parent_state, input_state_diff)
        .expect("failed to execute client");

    // Commit the state diff.
    println!("cycle-tracker-start: serialize state diff");
    let serialized = rkyv::to_bytes::<rkyv::rancor::BoxedError>(&state_diff)
        .expect("failed to serialize state diff");
    println!("cycle-tracker-end: serialize state diff");
    println!("cycle-tracker-start: commit");
    sp1_zkvm::io::commit(&transactions);
    sp1_zkvm::io::commit_slice(&serialized);
    println!("cycle-tracker-end: commit");
}
