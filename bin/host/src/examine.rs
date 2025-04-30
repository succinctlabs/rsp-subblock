use reth_primitives::hex_literal;
use reth_trie::{HashedPostState, TrieAccount};
use rsp_mpt::EthereumState;

const BIG_STATE_BYTES: &[u8] = include_bytes!("../../../big_state.bin");
const STATE_DIFF_BYTES: &[u8] = include_bytes!("../../../state_diff.bin");
const DEBUG_STATE_BYTES: &[u8] = include_bytes!("../../../debug_state.bin");

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let problem_address =
        hex_literal::hex!("0x00696ae3f9d462900e6af1d06d5ce49e0095874a086286234229b60eee11a37d");
    let big_state_bytes = std::fs::read("big_state.bin").unwrap();
    let big_state =
        rkyv::from_bytes::<EthereumState, rkyv::rancor::Error>(&big_state_bytes).unwrap();
    println!(
        "big_state state account: {:?}",
        big_state.state_trie.get_rlp::<TrieAccount>(&problem_address)
    );
    println!(
        "big_state storage trie: {:?}",
        big_state.storage_tries.get(&problem_address).unwrap()
    );
    let debug_state_bytes = std::fs::read("debug_state.bin").unwrap();
    let debug_state = bincode::deserialize::<EthereumState>(&debug_state_bytes).unwrap();
    println!(
        "debug_state state account: {:?}",
        debug_state.state_trie.get_rlp::<TrieAccount>(&problem_address)
    );
    println!(
        "debug_state storage trie: {:?}",
        debug_state.storage_tries.get(&problem_address).unwrap()
    );
    let state_diff: HashedPostState = bincode::deserialize(STATE_DIFF_BYTES).unwrap();
    println!("state_diff: {:?}", state_diff);
    Ok(())
}
