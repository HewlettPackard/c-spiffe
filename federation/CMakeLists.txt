# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "federation")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_FEDERATION 
${PROJECT_SOURCE_DIR}/endpoint.c
${PROJECT_SOURCE_DIR}/watcher.c
${PROJECT_SOURCE_DIR}/server.c
${PROJECT_SOURCE_DIR}/../utils/util.c
${PROJECT_SOURCE_DIR}/../bundle/spiffebundle/source.c
)

add_library(${TARGET_NAME} SHARED ${LIB_FEDERATION})
target_link_libraries(${TARGET_NAME} 
    curl
    spiffeid
    bundle
    internal
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

# Install higher level header:
set(HEADERS_MOD_FEDERATION
${PROJECT_SOURCE_DIR}/../include/c-spiffe/federation/federation.h
)
#   - *.h -> <prefix>/include/c-spiffe/*.h
install(
    FILES ${HEADERS_MOD_FEDERATION}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}"
)

set(WATCHER_EXAMPLE
${PROJECT_SOURCE_DIR}/watcher_example.c
)
add_executable(watcher_example "${WATCHER_EXAMPLE}")
target_link_libraries(watcher_example federation pthread)
