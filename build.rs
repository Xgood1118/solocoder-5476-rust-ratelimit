fn main() {
    #[cfg(feature = "grpc")]
    {
        let protoc_path = protobuf_src::protoc();
        std::env::set_var("PROTOC", protoc_path);

        tonic_build::compile_protos("proto/ratelimit.proto")
            .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));
    }
}
