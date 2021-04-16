# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "bundle")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_BUNDLE 
${PROJECT_SOURCE_DIR}/jwtbundle/src/bundle.c
${PROJECT_SOURCE_DIR}/jwtbundle/src/set.c
${PROJECT_SOURCE_DIR}/jwtbundle/src/source.c
${PROJECT_SOURCE_DIR}/x509bundle/src/bundle.c
${PROJECT_SOURCE_DIR}/x509bundle/src/set.c
${PROJECT_SOURCE_DIR}/x509bundle/src/source.c
)

add_library(${TARGET_NAME} SHARED ${LIB_BUNDLE})

# Install lib:
install(
    TARGETS              "${TARGET_NAME}"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)

# Install Headers:
set(HEADERS_BUNDLE_JWT
${PROJECT_SOURCE_DIR}/jwtbundle/src/bundle.h
${PROJECT_SOURCE_DIR}/jwtbundle/src/set.h
${PROJECT_SOURCE_DIR}/jwtbundle/src/source.h
)
#   - *.h -> <prefix>/include/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_BUNDLE_JWT}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}/jwtbundle/src"
)

# Install Headers:
set(HEADERS_BUNDLE_X509
${PROJECT_SOURCE_DIR}/x509bundle/src/bundle.h
${PROJECT_SOURCE_DIR}/x509bundle/src/set.h
${PROJECT_SOURCE_DIR}/x509bundle/src/source.h
)
#   - *.h -> <prefix>/include/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_BUNDLE_X509}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}/x509bundle/src"
)
