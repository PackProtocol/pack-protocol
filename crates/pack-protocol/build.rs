fn main() {
    let file_descriptors = protox::compile(&["proto/pack.proto"], &["proto/"])
        .expect("Failed to parse protobuf definitions");

    prost_build::compile_fds(file_descriptors)
        .expect("Failed to generate protobuf code");
}
