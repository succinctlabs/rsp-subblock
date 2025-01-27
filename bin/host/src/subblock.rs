use alloy_provider::ReqwestProvider;
use clap::Parser;
use eth_proofs::EthProofsClient;
use execute::process_execution_report;
use reth_primitives::B256;
use rsp_client_executor::{
    io::ClientExecutorInput, ChainVariant, CHAIN_ID_ETH_MAINNET, CHAIN_ID_LINEA_MAINNET,
    CHAIN_ID_OP_MAINNET, CHAIN_ID_SEPOLIA,
};
use rsp_host_executor::HostExecutor;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::path::PathBuf;
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

mod execute;

mod cli;
use cli::ProviderArgs;

mod eth_proofs;

/// The arguments for the host executable.
#[derive(Debug, Clone, Parser)]
struct HostArgs {
    /// The block number of the block to execute.
    #[clap(long)]
    block_number: u64,
    #[clap(flatten)]
    provider: ProviderArgs,
    /// Whether to generate a proof or just execute the block.
    #[clap(long)]
    prove: bool,
    /// Optional path to the directory containing cached client input. A new cache file will be
    /// created from RPC data if it doesn't already exist.
    #[clap(long)]
    cache_dir: Option<PathBuf>,
    /// The path to the CSV file containing the execution data.
    #[clap(long, default_value = "report.csv")]
    report_path: PathBuf,

    /// Optional ETH proofs endpoint.
    #[clap(long, env, requires("eth_proofs_api_token"))]
    eth_proofs_endpoint: Option<String>,

    /// Optional ETH proofs API token.
    #[clap(long, env)]
    eth_proofs_api_token: Option<String>,

    /// Optional ETH proofs cluster ID.
    #[clap(long, default_value_t = 1)]
    eth_proofs_cluster_id: u64,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Intialize the environment variables.
    dotenv::dotenv().ok();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    // Initialize the logger.
    tracing_subscriber::registry().with(fmt::layer()).with(EnvFilter::from_default_env()).init();

    // Parse the command line arguments.
    let args = HostArgs::parse();
    let provider_config = args.provider.clone().into_provider().await?;
    let eth_proofs_client = EthProofsClient::new(
        args.eth_proofs_cluster_id,
        args.eth_proofs_endpoint,
        args.eth_proofs_api_token,
    );

    if let Some(eth_proofs_client) = &eth_proofs_client {
        eth_proofs_client.queued(args.block_number).await?;
    }

    let variant = match provider_config.chain_id {
        CHAIN_ID_ETH_MAINNET => ChainVariant::Ethereum,
        CHAIN_ID_OP_MAINNET => ChainVariant::Optimism,
        CHAIN_ID_LINEA_MAINNET => ChainVariant::Linea,
        CHAIN_ID_SEPOLIA => ChainVariant::Sepolia,
        _ => {
            eyre::bail!("unknown chain ID: {}", provider_config.chain_id);
        }
    };

    let rpc_url = provider_config.rpc_url.expect("RPC URL is required");

    // Setup the provider.
    let provider = ReqwestProvider::new_http(rpc_url);

    // Setup the host executor.
    let host_executor = HostExecutor::new(provider);

    // Execute the host.
    let client_inputs =
        host_executor.execute_subblock(args.block_number).await.expect("failed to execute host");

    // Generate the proof.
    let client = ProverClient::from_env();

    // Setup the proving key and verification key.
    let (pk, vk) = client.setup(include_elf!("rsp-client-eth-subblock"));

    for input in client_inputs {
        // Execute the block inside the zkVM.
        let mut stdin = SP1Stdin::new();
        let buffer = bincode::serialize(&input).unwrap();
        stdin.write_vec(buffer);

        // Only execute the program.
        let (mut public_values, execution_report) = client.execute(&pk.elf, &stdin).run().unwrap();

        // Read the block hash.
        let state_root = public_values.read::<B256>();
        println!("success: intermediate state root ={state_root}");
    }

    // if args.prove {
    //     println!("Starting proof generation.");

    //     if let Some(eth_proofs_client) = &eth_proofs_client {
    //         eth_proofs_client.proving(args.block_number).await?;
    //     }

    //     let start = std::time::Instant::now();
    //     let proof = client.prove(&pk, &stdin).compressed().run().expect("Proving should work.");
    //     let proof_bytes = bincode::serialize(&proof.proof).unwrap();
    //     let elapsed = start.elapsed().as_secs_f32();

    //     if let Some(eth_proofs_client) = &eth_proofs_client {
    //         eth_proofs_client
    //             .proved(&proof_bytes, args.block_number, &execution_report, elapsed, &vk)
    //             .await?;
    //     }
    // }

    Ok(())
}

fn try_load_input_from_cache(
    cache_dir: Option<&PathBuf>,
    chain_id: u64,
    block_number: u64,
) -> eyre::Result<Option<ClientExecutorInput>> {
    Ok(if let Some(cache_dir) = cache_dir {
        let cache_path = cache_dir.join(format!("input/{}/{}.bin", chain_id, block_number));

        if cache_path.exists() {
            // TODO: prune the cache if invalid instead
            let mut cache_file = std::fs::File::open(cache_path)?;
            let client_input: ClientExecutorInput = bincode::deserialize_from(&mut cache_file)?;

            Some(client_input)
        } else {
            None
        }
    } else {
        None
    })
}
