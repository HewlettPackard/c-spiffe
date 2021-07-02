# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "logger")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_LOGGER
${PROJECT_SOURCE_DIR}/logger.c
${PROJECT_SOURCE_DIR}/../utils/util.c
)

add_library(${TARGET_NAME} SHARED ${LIB_LOGGER})

# Install lib:
install(
    TARGETS              "${TARGET_NAME}"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)

# Install higher level header:
set(HEADERS_MOD_LOGGER
${PROJECT_SOURCE_DIR}/logger.h
)
#   - *.h -> <prefix>/include/c-spiffe/*.h
install(
    FILES ${HEADERS_MOD_LOGGER}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}"
)
