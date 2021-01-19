# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

project(Workload VERSION 0.0.1 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 11)
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
find_package(OpenSSL REQUIRED)

# Include generated *.pb.h files
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(
    ${PROJECT_ROOT_DIR}/svid/
    ${PROJECT_ROOT_DIR}/internal/
    ${PROJECT_ROOT_DIR}/spiffeid/
)

set(CLIENT_SOURCES
  ${PROJECT_ROOT_DIR}/bundle/jwtbundle/src/bundle.c
  ${PROJECT_ROOT_DIR}/bundle/jwtbundle/src/set.c
  ${PROJECT_ROOT_DIR}/bundle/spiffebundle/src/bundle.c
  ${PROJECT_ROOT_DIR}/bundle/spiffebundle/src/set.c
  ${PROJECT_ROOT_DIR}/bundle/x509bundle/src/bundle.c
  ${PROJECT_ROOT_DIR}/bundle/x509bundle/src/set.c
  ${PROJECT_ROOT_DIR}/internal/cryptoutil/src/keys.c
  ${PROJECT_ROOT_DIR}/internal/jwtutil/src/util.c
  ${PROJECT_ROOT_DIR}/internal/pemutil/src/pem.c
  ${PROJECT_ROOT_DIR}/internal/x509util/src/certpool.c
  ${PROJECT_ROOT_DIR}/internal/x509util/src/util.c
  ${PROJECT_ROOT_DIR}/spiffeid/src/id.c
  ${PROJECT_ROOT_DIR}/spiffeid/src/match.c
  ${PROJECT_ROOT_DIR}/spiffeid/src/trustdomain.c
  ${PROJECT_ROOT_DIR}/spiffetls/tlsconfig/src/authorizer.c
  ${PROJECT_ROOT_DIR}/svid/x509svid/src/svid.c
  ${PROJECT_ROOT_DIR}/svid/x509svid/src/verify.c
  ${PROJECT_ROOT_DIR}/utils/src/util.c
  # ${PROJECT_ROOT_DIR}/workload/src/client.cc
  # ${PROJECT_ROOT_DIR}/workload/src/requestor.cpp
)

add_executable(client "client.cc" "requestor.cc"
# ${CLIENT_SOURCES}
  ${proto_srcs}
  ${grpc_srcs})

add_library(client_libs ${CLIENT_SOURCES})

target_link_libraries(client
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_GRPC_GRPC}
  ${_PROTOBUF_LIBPROTOBUF}
  pthread 
  client_libs ssl cjose jansson subunit m rt pthread uriparser crypto)

  
  add_executable(grpc_conn_test "grpc_conn_test.cc"
  ${proto_srcs}
  ${grpc_srcs})
target_link_libraries(grpc_conn_test
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_GRPC_GRPC}
  ${_PROTOBUF_LIBPROTOBUF}
  pthread )
