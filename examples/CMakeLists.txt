# (C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP
#
# 
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# 
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# 
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

# spiffe-tls
set(CLIENT_TLS
    spiffe-tls/client/main.c
)
add_executable(spiffe_tls_client "${CLIENT_TLS}")
target_link_libraries(spiffe_tls_client spiffetls)

set(SERVER_TLS
    spiffe-tls/server/main.c
)
add_executable(spiffe_tls_server "${SERVER_TLS}")
target_link_libraries(spiffe_tls_server spiffetls)

# spiffe-jwt
set(CLIENT_JWT
    spiffe-jwt/client/main.c
)
add_executable(spiffe_jwt_client "${CLIENT_JWT}")
target_link_libraries(spiffe_jwt_client spiffetls curl)

set(SERVER_JWT
    spiffe-jwt/server/main.c
)
add_executable(spiffe_jwt_server "${SERVER_JWT}")
target_link_libraries(spiffe_jwt_server spiffetls)

# spiffe-jwt-using-proxy
set(CLIENT_JWT_PROXY
    spiffe-jwt-using-proxy/client/main.c
)
add_executable(spiffe_jwt_proxy_client "${CLIENT_JWT_PROXY}")
target_link_libraries(spiffe_jwt_proxy_client spiffetls curl)

set(SERVER_JWT_PROXY
    spiffe-jwt-using-proxy/server/main.c
)
add_executable(spiffe_jwt_proxy_server "${SERVER_JWT_PROXY}")
target_link_libraries(spiffe_jwt_proxy_server spiffetls)

# spiffe-http
set(CLIENT_HTTP
    spiffe-http/client/main.c
)
add_executable(spiffe_http_client "${CLIENT_HTTP}")
target_link_libraries(spiffe_http_client spiffetls curl)

set(SERVER_HTTP
    spiffe-http/server/main.c
)
add_executable(spiffe_http_server "${SERVER_HTTP}")
target_link_libraries(spiffe_http_server spiffetls)

set (proto_name helloworld)

# Get proto files
get_filename_component(proto "spiffe-grpc/${proto_name}.proto" ABSOLUTE)
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
