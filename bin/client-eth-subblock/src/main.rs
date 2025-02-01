#![no_main]
sp1_zkvm::entrypoint!(main);

use rsp_client_executor::{io::SimpleClientExecutorInput, ClientExecutor, EthereumVariant};

pub fn main() {
    // Read the input.
    let input = sp1_zkvm::io::read_vec();
    let input = bincode::deserialize::<SimpleClientExecutorInput>(&input).unwrap();
    sp1_zkvm::io::commit(&input);

    // Execute the block.
    let executor = ClientExecutor;
    let state_diff =
        executor.execute_subblock::<EthereumVariant>(input).expect("failed to execute client");

    // Commit the state diff. TODO TODO TODO
    sp1_zkvm::io::commit(&0u32);
}
