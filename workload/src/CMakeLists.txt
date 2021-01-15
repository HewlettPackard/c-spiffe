# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

project(Workload VERSION 0.0.1 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE RelWithDebInfo)

set (proto_name workload)

# Get proto files
get_filename_component(proto "../../protos/${proto_name}.proto" ABSOLUTE)
get_filename_component(proto_dir "${proto}" DIRECTORY)

# Generate source files
set(proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.pb.cc")
set(proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.pb.h")
set(grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.grpc.pb.cc")
set(grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.grpc.pb.h")
add_custom_command(
    OUTPUT "${proto_srcs}" "${proto_hdrs}" "${grpc_srcs}" "${grpc_hdrs}"
    COMMAND ${_PROTOBUF_PROTOC}
    ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
    --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
    -I "${proto_dir}"
    --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
    "${proto}"
    DEPENDS "${proto}"
)

# Include generated *.pb.h files
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(
    ${PROJECT_ROOT_DIR}/svid/
)

add_executable(client "client.cc" "requestor.cpp" "../../svid/x509svid/src/svid.c"
  ${proto_srcs}
  ${grpc_srcs})
target_link_libraries(client
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_GRPC_GRPC}
  ${_PROTOBUF_LIBPROTOBUF}
  pthread )
  
  add_executable(grpc_conn_test "grpc_conn_test.cc"
  ${proto_srcs}
  ${grpc_srcs})
target_link_libraries(grpc_conn_test
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_GRPC_GRPC}
  ${_PROTOBUF_LIBPROTOBUF}
  pthread )
