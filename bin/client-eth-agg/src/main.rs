#![no_main]
sp1_zkvm::entrypoint!(main);

use rsp_client_executor::{
    io::{AggregationInput, SubblockOutput},
    ClientExecutor, EthereumVariant,
};

pub fn main() {
    // Read the input.
    println!("cycle-tracker-start: deserialize");
    // Read the public values, vkey, and aggregation input.
    let public_values = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    let vkey = sp1_zkvm::io::read::<[u32; 8]>();
    let input = sp1_zkvm::io::read_vec();
    let aggregation_input = bincode::deserialize::<AggregationInput>(&input).unwrap();
    println!("cycle-tracker-end: deserialize");

    let client = ClientExecutor;

    let header = client
        .execute_aggregation::<EthereumVariant>(public_values, vkey, aggregation_input)
        .expect("failed to execute aggregation");

    let hash = header.hash_slow();

    sp1_zkvm::io::commit(&hash);
}
