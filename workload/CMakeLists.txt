# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "workload")
project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE RelWithDebInfo)

find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)
set (proto_name ${TARGET_NAME})


# Get proto files
get_filename_component(proto "../protos/${proto_name}.proto" ABSOLUTE)
get_filename_component(proto_dir "${proto}" DIRECTORY)

# Generate source files
set(proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.pb.cc")
set(proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.pb.h")
set(grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.grpc.pb.cc")
set(grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.grpc.pb.h")
set(grpc_mock "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}_mock.grpc.pb.h")
add_custom_command(
    OUTPUT "${proto_srcs}" "${proto_hdrs}" "${grpc_srcs}" "${grpc_hdrs}"
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

set(OWN_LIBS 
libsvid
libspiffeid
libinternal
libbundle
)

set(EXT_LIBS
OpenSSL::SSL
uriparser
jansson
cjose
subunit
rt
m
pthread
ssl
crypto)

set(LIB_REQUESTOR
  src/requestor.cc
  ${proto_srcs}
  ${grpc_srcs}
)

add_library(librequestor SHARED ${LIB_REQUESTOR})

target_link_libraries(librequestor
${OWN_LIBS}
${EXT_LIBS}
${_REFLECTION}
${_GRPC_GRPCPP}
${_GRPC_GRPC}
${_PROTOBUF_LIBPROTOBUF}
)

set(CPP_CLIENT
    src/cpp_client_example.cc
)
add_executable(cpp_client "${CPP_CLIENT}")
target_link_libraries(cpp_client librequestor)

set(C_CLIENT
    src/c_client_example.c
)
add_executable(c_client "${C_CLIENT}")
target_link_libraries(c_client librequestor)
