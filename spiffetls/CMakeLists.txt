# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "spiffetls")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_SPIFFETLS
${PROJECT_SOURCE_DIR}/tlsconfig/config.c
${PROJECT_SOURCE_DIR}/tlsconfig/authorizer.c
${PROJECT_SOURCE_DIR}/dial.c
${PROJECT_SOURCE_DIR}/listen.c
${PROJECT_SOURCE_DIR}/mode.c
${PROJECT_SOURCE_DIR}/peerid.c)

set(C_DIAL
    c_dial_example.c
)
add_executable(c_dial "${C_DIAL}")
target_link_libraries(c_dial spiffetls)

set(C_LISTEN
    c_listen_example.c
)
add_executable(c_listen "${C_LISTEN}")
target_link_libraries(c_listen spiffetls)

add_library(${TARGET_NAME} SHARED ${LIB_SPIFFETLS})

target_link_libraries(${TARGET_NAME}
    svid
    ssl
    spiffeid
    internal
    bundle
    client
    uriparser
    jansson
    cjose
    subunit
    rt
    m
    pthread
    crypto)

# Install Headers:
set(HEADERS_SPIFFETLS
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffetls/dial.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffetls/listen.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffetls/mode.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffetls/option.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffetls/peerid.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_SPIFFETLS}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}"
)

# Install Headers:
set(HEADERS_TLSCONFIG
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffetls/tlsconfig/authorizer.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffetls/tlsconfig/config.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffetls/tlsconfig/trace.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_TLSCONFIG}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}"
)

# Install higher level header:
set(HEADERS_MOD_SPIFFETLS
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffetls/spiffetls.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/spiffetls/tlsconfig.h
)
#   - *.h -> <prefix>/include/c-spiffe/*.h
install(
    FILES ${HEADERS_MOD_SPIFFETLS}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}"
)
