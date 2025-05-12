use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    let llvm_pass_pipeline = [
        "module(wholeprogramdevirt,globalopt,always-inline)",
        "function(simplifycfg,gvn,reassociate,loop-unroll,loop-vectorize,slp-vectorizer)",
    ]
    .join(",");

    let rustflags: Vec<String> = vec![
        "-Cllvm-args=-inline-threshold=1000".to_string(),
        "-Ccodegen-units=1".to_string(),
        "-Copt-level=3".to_string(),
        "-C".to_string(),
        format!("passes={}", llvm_pass_pipeline),
        "-Cllvm-args=-inline-cold-callsite-threshold=1000".to_string(),
        "-Cllvm-args=-hot-callsite-threshold=1000".to_string(),
        "-Cllvm-args=-locally-hot-callsite-threshold=1000".to_string(),
        "-Cllvm-args=-inlinehint-threshold=1000".to_string(),
    ];
    build_program_with_args(
        "../client-eth",
        BuildArgs { ignore_rust_version: true, rustflags: rustflags.clone(), ..Default::default() },
    );
    build_program_with_args(
        "../client-eth-agg",
        BuildArgs { ignore_rust_version: true, rustflags: rustflags.clone(), ..Default::default() },
    );
    build_program_with_args(
        "../client-eth-subblock",
        BuildArgs { ignore_rust_version: true, rustflags: rustflags.clone(), ..Default::default() },
    );
}
