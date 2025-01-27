#![no_main]
sp1_zkvm::entrypoint!(main);

use reth_primitives::{Bloom, B256};
use rsp_client_executor::{io::ClientExecutorInput, ClientExecutor, EthereumVariant};

pub fn main() {
    // Commit the block hash.
    sp1_zkvm::io::commit(&0u32);
}
