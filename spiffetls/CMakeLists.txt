# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "spiffetls")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_SPIFFETLS
${PROJECT_SOURCE_DIR}/tlsconfig/src/config.c
${PROJECT_SOURCE_DIR}/tlsconfig/src/authorizer.c
${PROJECT_SOURCE_DIR}/src/dial.c
${PROJECT_SOURCE_DIR}/src/mode.c)

add_library(${TARGET_NAME} SHARED ${LIB_SPIFFETLS})

target_link_libraries(${TARGET_NAME}
    svid
    spiffeid
    internal
    bundle
    source
    OpenSSL::SSL
    uriparser
    jansson
    cjose
    subunit
    rt
    m
    pthread
    ssl
    crypto)
