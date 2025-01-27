#![no_main]
sp1_zkvm::entrypoint!(main);

use rsp_client_executor::{io::ClientExecutorInput, ClientExecutor, EthereumVariant};

pub fn main() {
    // Read the input.
    let input = sp1_zkvm::io::read_vec();
    let input = bincode::deserialize::<ClientExecutorInput>(&input).unwrap();

    // Execute the block.
    let executor = ClientExecutor;
    let state_root =
        executor.execute_subblock::<EthereumVariant>(input).expect("failed to execute client");

    // Commit the block hash.
    sp1_zkvm::io::commit(&state_root);
}
