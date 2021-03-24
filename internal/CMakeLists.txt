# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "internal")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)


set(LIB_INTERNAL 
${PROJECT_SOURCE_DIR}/cryptoutil/src/keys.c
${PROJECT_SOURCE_DIR}/jwtutil/src/util.c
${PROJECT_SOURCE_DIR}/pemutil/src/pem.c
${PROJECT_SOURCE_DIR}/x509util/src/certpool.c
${PROJECT_SOURCE_DIR}/x509util/src/util.c
${PROJECT_SOURCE_DIR}/../utils/src/util.c
)

add_library(${TARGET_NAME} SHARED ${LIB_INTERNAL})

install(
    TARGETS              "${TARGET_NAME}"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)

# Headers:
set(HEADERS_INTERNAL_CRYPTO
${PROJECT_SOURCE_DIR}/cryptoutil/src/keys.h
)

install(
    FILES ${HEADERS_INTERNAL_CRYPTO}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}/cryptoutil/src"
)

set(HEADERS_INTERNAL_JWT
${PROJECT_SOURCE_DIR}/jwtutil/src/util.h
)

install(
    FILES ${HEADERS_INTERNAL_JWT}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}/jwtutil/src"
)

set(HEADERS_INTERNAL_PEM
${PROJECT_SOURCE_DIR}/pemutil/src/pem.h
)

install(
    FILES ${HEADERS_INTERNAL_PEM}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}/pemutil/src"
)

set(HEADERS_INTERNAL_X509
${PROJECT_SOURCE_DIR}/x509util/src/certpool.h
${PROJECT_SOURCE_DIR}/x509util/src/util.h
)

install(
    FILES ${HEADERS_INTERNAL_X509}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}/x509util/src"
)

set(HEADERS_UTIL
${PROJECT_SOURCE_DIR}/../utils/src/util.h
)

install(
    FILES ${HEADERS_UTIL}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/util/src"
)

