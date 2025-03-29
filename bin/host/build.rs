use sp1_build::build_program;

fn main() {
    build_program("../client-eth");
    build_program("../client-eth-agg");
    build_program("../client-eth-subblock");
}
