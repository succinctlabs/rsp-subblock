#![no_main]
sp1_zkvm::entrypoint!(main);

use rsp_client_executor::{io::SubblockInput, ClientExecutor, EthereumVariant};

pub fn main() {
    // Read the input.
    let input = sp1_zkvm::io::read_vec();
    let input = bincode::deserialize::<SubblockInput>(&input).unwrap();
    sp1_zkvm::io::commit(&input);

    // Execute the block.
    let executor = ClientExecutor;
    let state_diff =
        executor.execute_subblock::<EthereumVariant>(input).expect("failed to execute client");

    // Commit the state diff.
    sp1_zkvm::io::commit(&state_diff);
}
