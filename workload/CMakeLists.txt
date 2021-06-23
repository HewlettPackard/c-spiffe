# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "workload")
project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C CXX)
#set(CMAKE_CXX_STANDARD 14)
#set(CMAKE_BUILD_TYPE RelWithDebInfo)

# find_package(OpenSSL REQUIRED)
# find_package(GTest REQUIRED)
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
svid
spiffeid
internal
bundle
)

set(EXT_LIBS
uriparser
jansson
cjose
subunit
rt
m
pthread
crypto)


# Install Headers:
set(HEADERS_SOURCE
${PROJECT_SOURCE_DIR}/../include/c-spiffe/workload/x509source.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/workload/jwtsource.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_SOURCE}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}"
)

set(LIB_WATCHER
${PROJECT_SOURCE_DIR}/watcher.c
${PROJECT_SOURCE_DIR}/jwtwatcher.c
)

# Install Headers:
set(HEADERS_WATCHER
${PROJECT_SOURCE_DIR}/../include/c-spiffe/workload/watcher.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/workload/x509context.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/workload/jwtcallback.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/workload/jwtwatcher.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_WATCHER}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}"
)

set(LIB_BACKOFF
${PROJECT_SOURCE_DIR}/backoff.c
)

# Install Headers:
set(HEADERS_BACKOFF
${PROJECT_SOURCE_DIR}/../include/c-spiffe/workload/backoff.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_BACKOFF}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}"
)

set(LIB_CLIENT
${PROJECT_SOURCE_DIR}/client.cc
${PROJECT_SOURCE_DIR}/../svid/jwtsvid/parse.c
${PROJECT_SOURCE_DIR}/../svid/x509svid/verify.c
${PROJECT_SOURCE_DIR}/../svid/x509svid/source.c
${PROJECT_SOURCE_DIR}/../bundle/jwtbundle/source.c
${PROJECT_SOURCE_DIR}/../bundle/x509bundle/source.c
${PROJECT_SOURCE_DIR}/jwtsource.c
${PROJECT_SOURCE_DIR}/x509source.c
${proto_srcs}
${grpc_srcs}
)
# Install Headers:
set(HEADERS_CLIENT
${PROJECT_SOURCE_DIR}/../include/c-spiffe/workload/client.h
${proto_hdrs}
${grpc_hdrs}
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_CLIENT}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}"
)

add_library(backoff SHARED ${LIB_BACKOFF})
target_link_libraries(backoff
${OWN_LIBS}
${EXT_LIBS}
)

add_library(client SHARED ${LIB_CLIENT} ${LIB_WATCHER})

target_link_libraries(client
backoff
${OWN_LIBS}
${EXT_LIBS}
${_REFLECTION}
${_GRPC_GRPCPP}
${_GRPC_GRPC}
${_PROTOBUF_LIBPROTOBUF}
)

target_link_libraries(
client
${OWN_LIBS}
${EXT_LIBS}
)

# Install lib:
install(
    TARGETS              "backoff" "client"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)

set(CPP_CLIENT
${PROJECT_SOURCE_DIR}/cpp_client_example.cc
)
add_executable(cpp_client "${CPP_CLIENT}")
target_link_libraries(cpp_client client)

set(C_CLIENT
${PROJECT_SOURCE_DIR}/c_client_example.c
)
add_executable(c_client "${C_CLIENT}")
target_link_libraries(c_client client)

set(C_CLIENT_BUNDLE
${PROJECT_SOURCE_DIR}/c_client_example_bundle.c
)
add_executable(c_client_bundle "${C_CLIENT_BUNDLE}")
target_link_libraries(c_client_bundle client)

set(WATCH_JWT_BUNDLES
${PROJECT_SOURCE_DIR}/watch_jwt_bundles.c
)
add_executable(example_watch_jwt_bundles "${WATCH_JWT_BUNDLES}")
target_link_libraries(example_watch_jwt_bundles client)

set(C_CLIENT_VALIDATE
${PROJECT_SOURCE_DIR}/c_client_example_validate.c
)
add_executable(c_client_validate "${C_CLIENT_VALIDATE}")
target_link_libraries(c_client_validate client)

set(JWTSOURCE_EXAMPLE
${PROJECT_SOURCE_DIR}/jwtsource_example.c
)
add_executable(jwtsource_example "${JWTSOURCE_EXAMPLE}")
target_link_libraries(jwtsource_example client)

# Install higher level header:
set(HEADERS_MOD_WORKLOAD
${PROJECT_SOURCE_DIR}/../include/c-spiffe/workload/workload.h
)
#   - *.h -> <prefix>/include/c-spiffe/*.h
install(
    FILES ${HEADERS_MOD_WORKLOAD}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}"
)
