$ protoc -I . --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` worload.proto
$ protoc -I . --cpp_out=. wordload.proto
