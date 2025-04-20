use std::time::{SystemTime, UNIX_EPOCH};

use alloy_provider::{network::AnyNetwork, Provider as _, ReqwestProvider};
use api2::conn::ClusterConnection;
use api2::worker::CreateDummyProofRequest;
use clap::Parser;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sp1_sdk::{SP1ProofWithPublicValues, SP1Stdin};
use sp1_worker::V2Client;
use sp1_worker::{
    artifact::{ArtifactClient, ArtifactType},
    proto::{Artifact, TaskType},
    ProofOptions,
};
use url::Url;

/// The arguments for configuring the chain data provider.
#[derive(Debug, Clone, Parser)]
pub struct ProviderArgs {
    /// The rpc url used to fetch data about the block. If not provided, will use the
    /// RPC_{chain_id} env var.
    #[clap(long)]
    rpc_url: Option<Url>,
    /// The chain ID. If not provided, requires the rpc_url argument to be provided.
    #[clap(long)]
    chain_id: Option<u64>,
}

pub struct ProviderConfig {
    pub rpc_url: Option<Url>,
    pub chain_id: u64,
}

impl ProviderArgs {
    pub async fn into_provider(self) -> eyre::Result<ProviderConfig> {
        // We don't need RPC when using cache with known chain ID, so we leave it as `Option<Url>`
        // here and decide on whether to panic later.
        //
        // On the other hand chain ID is always needed.
        let (rpc_url, chain_id) = match (self.rpc_url, self.chain_id) {
            (Some(rpc_url), Some(chain_id)) => (Some(rpc_url), chain_id),
            (None, Some(chain_id)) => {
                match std::env::var(format!("RPC_{}", chain_id)) {
                    Ok(rpc_env_var) => {
                        // We don't always need it but if the value exists it has to be valid.
                        (Some(Url::parse(rpc_env_var.as_str()).expect("invalid rpc url")), chain_id)
                    }
                    Err(_) => {
                        // Not having RPC is okay because we know chain ID.
                        (None, chain_id)
                    }
                }
            }
            (Some(rpc_url), None) => {
                // We can find out about chain ID from RPC.
                let provider: ReqwestProvider<AnyNetwork> =
                    ReqwestProvider::new_http(rpc_url.clone());
                let chain_id = provider.get_chain_id().await?;

                (Some(rpc_url), chain_id)
            }
            (None, None) => {
                eyre::bail!("either --rpc-url or --chain-id must be used")
            }
        };

        Ok(ProviderConfig { rpc_url, chain_id })
    }
}

pub(crate) async fn upload_artifact<T: Serialize + Send + Sync, A: ArtifactClient>(
    artifact_client: &A,
    name: &str,
    data: T,
    artifact_type: ArtifactType,
) -> eyre::Result<Artifact> {
    let artifact = artifact_client
        .create_artifact_blocking(name, 0)
        .map_err(|e| eyre::eyre!("Failed to create artifact: {}", e))?;
    artifact_client
        .upload_with_type(&artifact, artifact_type, data)
        .await
        .expect("failed to upload artifact");
    // artifact
    //     .upload_with_type(artifact_type, data)
    //     .await
    //     .map_err(|e| eyre::eyre!("Failed to upload artifact: {}", e))?;

    Ok(artifact)
}

pub(crate) async fn schedule_controller<A: ArtifactClient>(
    elf_artifact: Artifact,
    stdin: SP1Stdin,
    cluster_client: &mut ClusterConnection,
    artifact_client: &A,
    _execute: bool,
) -> eyre::Result<SP1ProofWithPublicValues> {
    let mut hasher = Sha256::new();
    for v in &stdin.buffer {
        hasher.update(v);
    }
    println!("subblock input: {:?}", hasher.finalize());
    // Convert to seconds and then to string
    let now: std::time::Duration =
        SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");

    let proof_id = format!("rsp_{}", now.as_secs());

    let worker_id = format!("worker_{}", now.as_secs());

    println!("proof_id: {}", proof_id);
    let stdin_artifact: Artifact =
        upload_artifact(artifact_client, "subblock_stdin", stdin, ArtifactType::Stdin).await?;

    let proof_options = ProofOptions::subblock();
    let proof_options_artifact: Artifact = upload_artifact(
        artifact_client,
        "subblock_proof_options",
        proof_options,
        ArtifactType::UnspecifiedArtifactType,
    )
    .await?;
    // Create an empty artifact for the output
    let output_artifact: Artifact = artifact_client
        .create_artifact_blocking("subblock_output", 0)
        .map_err(|e| eyre::eyre!("Failed to create output artifact: {}", e))?;

    let input_ids = vec![elf_artifact.id, stdin_artifact.id, proof_options_artifact.id];

    cluster_client
        .client
        .client
        .create_dummy_proof(CreateDummyProofRequest {
            worker_id: worker_id.clone(),
            proof_id: proof_id.clone(),
            requester: "yuwens_mac".to_string(),
            expires_at: 0,
        })
        .await?;

    let task_id = cluster_client
        .client
        .create_task(
            TaskType::Sp1Controller,
            &input_ids,
            &[output_artifact.id.clone()],
            proof_id.clone(),
            None,
            None,
        )
        .await
        .map_err(|e| eyre::eyre!("Failed to create task: {}", e))?;

    println!("Task created: {}", task_id);
    cluster_client
        .client
        .wait_tasks(proof_id.clone(), &[task_id.clone()])
        .await
        .map_err(|e| eyre::eyre!("Failed to wait for task: {}", e))?;

    let result: SP1ProofWithPublicValues = artifact_client
        .download_with_type(&output_artifact, ArtifactType::Proof)
        .await
        .expect("failed to download proof");
    // println!("run again, this time setup is cached.");
    // cluster_client
    //     .client
    //     .update_task_status(&task_id, sp1_worker::proto::TaskStatus::Pending)
    //     .await
    //     .map_err(|e| eyre::eyre!("Failed to update task status: {}", e))?;

    // cluster_client
    //     .wait_tasks(&[task_id])
    //     .await
    //     .map_err(|e| eyre::eyre!("Failed to wait for task: {}", e))?;

    Ok(result)
}
