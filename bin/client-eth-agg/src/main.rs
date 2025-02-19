#![no_main]
sp1_zkvm::entrypoint!(main);

use rkyv::util::AlignedVec;
use rsp_client_executor::{io::AggregationInput, ClientExecutor, EthereumVariant};
use rsp_mpt::EthereumState;

pub fn main() {
    // Read the input.
    println!("cycle-tracker-start: deserialize");
    // Read the public values, vkey, and aggregation input.
    let public_values = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    let vkey = sp1_zkvm::io::read::<[u32; 8]>();
    println!("cycle-tracker-start: deserialize aggregation input");
    let aggregation_input = sp1_zkvm::io::read::<AggregationInput>();
    println!("cycle-tracker-end: deserialize aggregation input");

    println!("cycle-tracker-start: deserialize parent state");
    let parent_state_bytes = sp1_zkvm::io::read_vec();
    let mut aligned = AlignedVec::<16>::with_capacity(parent_state_bytes.len());
    aligned.extend_from_slice(&parent_state_bytes);
    let parent_state =
        rkyv::from_bytes::<EthereumState, rkyv::rancor::BoxedError>(&aligned).unwrap();
    println!("cycle-tracker-end: deserialize parent state");

    let client = ClientExecutor;

    let header = client
        .execute_aggregation::<EthereumVariant>(
            public_values,
            vkey,
            aggregation_input,
            parent_state,
        )
        .expect("failed to execute aggregation");

    let hash = header.hash_slow();

    sp1_zkvm::io::commit(&hash);
}
