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

set(TARGET_NAME "federation")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_FEDERATION 
${PROJECT_SOURCE_DIR}/endpoint.c
${PROJECT_SOURCE_DIR}/watcher.c
${PROJECT_SOURCE_DIR}/server.c
${PROJECT_SOURCE_DIR}/../utils/util.c
${PROJECT_SOURCE_DIR}/../utils/picohttpparser.c
${PROJECT_SOURCE_DIR}/../bundle/spiffebundle/source.c
)

add_library(${TARGET_NAME} SHARED ${LIB_FEDERATION})
target_link_libraries(${TARGET_NAME} 
    curl
    spiffeid
    bundle
    logger
    internal
    spiffetls
    cjose
    uriparser
)
# Install lib:
install(
    TARGETS              "${TARGET_NAME}"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)

# Install Headers:
set(HEADERS_FEDERATION
${PROJECT_SOURCE_DIR}/../include/c-spiffe/federation/endpoint.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/federation/watcher.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/federation/server.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_FEDERATION}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}"
)

set(ENDPOINT_EXAMPLE
    endpoint_example.c
)
add_executable(endpoint_example "${ENDPOINT_EXAMPLE}")
target_link_libraries(endpoint_example federation)

set(WATCHER_EXAMPLE
${PROJECT_SOURCE_DIR}/watcher_example.c
)
add_executable(watcher_example "${WATCHER_EXAMPLE}")
target_link_libraries(watcher_example federation pthread)

set(SERVER_EXAMPLE
${PROJECT_SOURCE_DIR}/server_example.c
)
add_executable(server_example "${SERVER_EXAMPLE}")
target_link_libraries(server_example federation pthread)

# Install higher level header:
set(HEADERS_MOD_FEDERATION
${PROJECT_SOURCE_DIR}/../include/c-spiffe/federation/federation.h
)
#   - *.h -> <prefix>/include/c-spiffe/*.h
install(
    FILES ${HEADERS_MOD_FEDERATION}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}"
)

