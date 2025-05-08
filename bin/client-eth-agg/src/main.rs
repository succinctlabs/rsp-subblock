#![no_main]
sp1_zkvm::entrypoint!(main);

use reth_primitives::B256;
use rsp_client_executor::{io::AggregationInput, ClientExecutor, EthereumVariant};

pub fn main() {
    // Read the input.
    println!("cycle-tracker-start: deserialize");
    // Read the public values, vkey, and aggregation input.
    let public_values = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    let vkey = sp1_zkvm::io::read::<[u32; 8]>();
    println!("cycle-tracker-start: deserialize aggregation input");
    let aggregation_input = sp1_zkvm::io::read::<AggregationInput>();
    println!("cycle-tracker-end: deserialize aggregation input");

    let parent_state_root = sp1_zkvm::io::read::<B256>();
    sp1_zkvm::io::commit(&parent_state_root);
    sp1_zkvm::io::commit(&aggregation_input.current_block);
    println!("cycle-tracker-end: deserialize");

    let client = ClientExecutor;

    let header = client
        .execute_aggregation::<EthereumVariant>(
            public_values,
            vkey,
            aggregation_input,
            parent_state_root,
        )
        .expect("failed to execute aggregation");

    let hash = header.hash_slow();

    sp1_zkvm::io::commit(&hash);
}
