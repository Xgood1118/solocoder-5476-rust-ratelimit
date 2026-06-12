fn main() {
    if std::env::var("CARGO_FEATURE_GRPC").is_ok() {
        tonic_build::compile_protos("proto/ratelimit.proto")
            .unwrap_or_else(|e| panic!("Failed to compile protos: {:?}. Ensure protoc is installed.", e));
    }

    println!("cargo:rerun-if-changed=proto/ratelimit.proto");
    println!("cargo:rerun-if-changed=build.rs");
}
