# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "federation")

set(LIB_FEDERATION 
${CMAKE_CURRENT_SOURCE_DIR}/endpoint.c
${CMAKE_CURRENT_SOURCE_DIR}/watcher.c
${CMAKE_CURRENT_SOURCE_DIR}/../utils/util.c
${CMAKE_CURRENT_SOURCE_DIR}/../bundle/spiffebundle/source.c
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
${CMAKE_CURRENT_SOURCE_DIR}/endpoint.h
${CMAKE_CURRENT_SOURCE_DIR}/watcher.h
)
#   - *.h -> <prefix>/include/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_FEDERATION}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}/src"
)

set(ENDPOINT_EXAMPLE
    endpoint_example.c
)
add_executable(endpoint_example "${ENDPOINT_EXAMPLE}")
target_link_libraries(endpoint_example federation)
