# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "spiffeid")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_SPIFFEID 
${PROJECT_SOURCE_DIR}/id.c
${PROJECT_SOURCE_DIR}/match.c
${PROJECT_SOURCE_DIR}/trustdomain.c
${PROJECT_SOURCE_DIR}/../utils/util.c
)

add_library(${TARGET_NAME} SHARED ${LIB_SPIFFEID})

# Install lib:
install(
    TARGETS              "${TARGET_NAME}"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)

# Install headers:
set(HEADERS_SPIFFEID
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffeid/id.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffeid/match.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffeid/trustdomain.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_SPIFFEID}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}"
)

# Install higher level header:
set(HEADERS_MOD_SPIFFEID
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffeid/spiffeid.h
)
#   - *.h -> <prefix>/include/c-spiffe/*.h
install(
    FILES ${HEADERS_MOD_SPIFFEID}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}"
)
