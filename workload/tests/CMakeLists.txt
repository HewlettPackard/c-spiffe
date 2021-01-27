# Minimum CMake required
cmake_minimum_required(VERSION 3.13)
set (proto_name "workload")
find_package(GTest REQUIRED)

# Get proto files
get_filename_component(proto "../../protos/${proto_name}.proto" ABSOLUTE)
get_filename_component(proto_dir "${proto}" DIRECTORY)

# Generate source files
set(proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.pb.cc")
set(proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.pb.h")
set(grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.grpc.pb.cc")
set(grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.grpc.pb.h")
set(grpc_mock "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}_mock.grpc.pb.h")
add_custom_command(
    OUTPUT "${proto_srcs}" "${proto_hdrs}" "${grpc_srcs}" "${grpc_hdrs}" "${grpc_mock}"
    COMMAND ${_PROTOBUF_PROTOC}
    ARGS --grpc_out "generate_mock_code=true:${CMAKE_CURRENT_BINARY_DIR}"
    --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
    -I "${proto_dir}"
    --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
    "${proto}"
    DEPENDS "${proto}"
)

# Include generated *.pb.h files
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(check_requestor "./check_requestor.cc" ${grpc_srcs} ${proto_srcs} ${grpc_mock})

target_link_libraries(check_requestor librequestor ${CHECK_LIBRARIES} gmock gmock_main gtest
  OpenSSL::SSL
  libspiffeid
  libinternal
  uriparser
  libbundle
  jansson
  cjose
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

  add_test(requestor-test check_requestor)
