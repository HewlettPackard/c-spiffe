# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "federation")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)


set(LIB_FEDERATION 
${PROJECT_SOURCE_DIR}/src/endpoint.c
${PROJECT_SOURCE_DIR}/../utils/src/util.c
${PROJECT_SOURCE_DIR}/../bundle/spiffebundle/src/source.c
)

add_library(${TARGET_NAME} SHARED ${LIB_FEDERATION})

# Install lib:
install(
    TARGETS              "${TARGET_NAME}"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)

# Install Headers:
set(HEADERS_FEDERATION
${PROJECT_SOURCE_DIR}/src/endpoint.h
)
#   - *.h -> <prefix>/include/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_FEDERATION}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}/src"
)
