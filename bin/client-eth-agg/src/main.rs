#![no_main]
sp1_zkvm::entrypoint!(main);

use rsp_client_executor::{
    io::{AggregationInput, SubblockOutput},
    ClientExecutor, EthereumVariant,
};

pub fn main() {
    // Read the input.
    println!("cycle-tracker-start: deserialize");
    let input = sp1_zkvm::io::read_vec();
    let subblock_outputs = bincode::deserialize::<Vec<SubblockOutput>>(&input).unwrap();

    let input = sp1_zkvm::io::read_vec();
    let aggregation_input = bincode::deserialize::<AggregationInput>(&input).unwrap();
    println!("cycle-tracker-end: deserialize");

    let client = ClientExecutor;

    let header = client
        .execute_aggregation::<EthereumVariant>(subblock_outputs, aggregation_input)
        .expect("failed to execute aggregation");

    let hash = header.hash_slow();

    sp1_zkvm::io::commit(&hash);
}
