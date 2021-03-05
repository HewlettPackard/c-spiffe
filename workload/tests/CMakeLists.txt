# Minimum CMake required
cmake_minimum_required(VERSION 3.13)
set (proto_name "workload")
find_package(GTest REQUIRED)


file(COPY ../tests/resources/ DESTINATION ${PROJECT_BINARY_DIR}/workload/tests/resources/)

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

SET(GCC_COVERAGE_COMPILE_FLAGS "-fprofile-arcs -ftest-coverage")
SET(GCC_COVERAGE_LINK_FLAGS    "-lgcov")
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")
SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

add_executable(check_client "./check_client.cc" ${grpc_srcs} ${proto_srcs} ${grpc_mock})

target_link_libraries(check_client ${CHECK_LIBRARIES} 
  client
  gtest
  gmock
  gmock_main
  OpenSSL::SSL
  spiffeid
  internal
  uriparser
  bundle
  jansson
  cjose
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_client check_client)

add_executable(check_watcher "./check_watcher.c")

target_link_libraries(check_watcher ${CHECK_LIBRARIES} 
client
 OpenSSL::SSL
  spiffeid
  internal
  uriparser
  bundle
  jansson
  cjose
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_watcher check_watcher)

add_executable(check_jwtwatcher "./check_jwtwatcher.c")

target_link_libraries(check_jwtwatcher ${CHECK_LIBRARIES} 
client
 OpenSSL::SSL
  spiffeid
  internal
  uriparser
  bundle
  jansson
  cjose
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_jwtwatcher check_jwtwatcher)

add_executable(check_x509source "./check_x509source.c")

target_link_libraries(check_x509source ${CHECK_LIBRARIES} 
  source
  OpenSSL::SSL
  spiffeid
  internal
  uriparser
  bundle
  jansson
  cjose
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_x509source check_x509source)
