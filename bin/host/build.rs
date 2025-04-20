use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    build_program_with_args(
        "../client-eth",
        BuildArgs { ignore_rust_version: true, ..Default::default() },
    );
    build_program_with_args(
        "../client-eth-agg",
        BuildArgs { ignore_rust_version: true, ..Default::default() },
    );
    build_program_with_args(
        "../client-eth-subblock",
        BuildArgs { ignore_rust_version: true, ..Default::default() },
    );
}
