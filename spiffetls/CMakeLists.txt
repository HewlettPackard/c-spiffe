# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "spiffetls")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_SPIFFETLS
${PROJECT_SOURCE_DIR}/tlsconfig/src/config.c
${PROJECT_SOURCE_DIR}/tlsconfig/src/authorizer.c
${PROJECT_SOURCE_DIR}/src/dial.c
${PROJECT_SOURCE_DIR}/src/mode.c
${PROJECT_SOURCE_DIR}/src/peerid.c)

set(C_DIAL
    src/c_dial_example.c
)
add_executable(c_dial "${C_DIAL}")
target_link_libraries(c_dial spiffetls)

add_library(${TARGET_NAME} SHARED ${LIB_SPIFFETLS})

target_link_libraries(${TARGET_NAME}
    svid
    ssl
    spiffeid
    internal
    bundle
    source
    uriparser
    jansson
    cjose
    subunit
    rt
    m
    pthread
    crypto)
