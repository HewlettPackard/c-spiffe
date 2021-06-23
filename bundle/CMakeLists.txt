# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "bundle")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_BUNDLE 
${PROJECT_SOURCE_DIR}/jwtbundle/bundle.c
${PROJECT_SOURCE_DIR}/jwtbundle/set.c
${PROJECT_SOURCE_DIR}/x509bundle/bundle.c
${PROJECT_SOURCE_DIR}/x509bundle/set.c
${PROJECT_SOURCE_DIR}/spiffebundle/bundle.c
${PROJECT_SOURCE_DIR}/spiffebundle/set.c
)

add_library(${TARGET_NAME} SHARED ${LIB_BUNDLE})

# Install lib:
install(
    TARGETS              "${TARGET_NAME}"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)

# Install Headers:
set(HEADERS_BUNDLE_JWT
${PROJECT_SOURCE_DIR}/../include/c-spiffe/bundle/jwtbundle/bundle.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/bundle/jwtbundle/set.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/bundle/jwtbundle/source.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_BUNDLE_JWT}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}/jwtbundle"
)

# Install Headers:
set(HEADERS_BUNDLE_X509
${PROJECT_SOURCE_DIR}/../include/c-spiffe/bundle/x509bundle/bundle.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/bundle/x509bundle/set.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/bundle/x509bundle/source.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_BUNDLE_X509}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}/x509bundle"
)

# Install Headers:
set(HEADERS_BUNDLE_SPIFFE
${PROJECT_SOURCE_DIR}/../include/c-spiffe/bundle/spiffebundle/bundle.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/bundle/spiffebundle/set.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/bundle/spiffebundle/source.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_BUNDLE_SPIFFE}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}/spiffebundle"
)

# Install higher level header:
set(HEADERS_MOD_BUNDLE
${PROJECT_SOURCE_DIR}/../include/c-spiffe/bundle/jwtbundle.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/bundle/spiffebundle.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/bundle/x509bundle.h
)
#   - *.h -> <prefix>/include/c-spiffe/*.h
install(
    FILES ${HEADERS_MOD_BUNDLE}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}"
)
