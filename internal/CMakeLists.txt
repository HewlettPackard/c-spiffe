# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "internal")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_INTERNAL 
${PROJECT_SOURCE_DIR}/cryptoutil/keys.c
${PROJECT_SOURCE_DIR}/jwtutil/util.c
${PROJECT_SOURCE_DIR}/pemutil/pem.c
${PROJECT_SOURCE_DIR}/x509util/certpool.c
${PROJECT_SOURCE_DIR}/x509util/util.c
${PROJECT_SOURCE_DIR}/../utils/util.c
)

add_library(${TARGET_NAME} SHARED ${LIB_INTERNAL})
# Install lib:
install(
    TARGETS              "${TARGET_NAME}"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)

# Install Headers:
set(HEADERS_INTERNAL_CRYPTO
${PROJECT_SOURCE_DIR}/../include/c-spiffe/internal/cryptoutil/keys.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_INTERNAL_CRYPTO}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}/cryptoutil"
)

# Install Headers:
set(HEADERS_INTERNAL_JWT
${PROJECT_SOURCE_DIR}/../include/c-spiffe/internal/jwtutil/util.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_INTERNAL_JWT}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}/jwtutil"
)

# Install Headers:
set(HEADERS_INTERNAL_PEM
${PROJECT_SOURCE_DIR}/../include/c-spiffe/internal/pemutil/pem.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_INTERNAL_PEM}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}/pemutil"
)

# Install Headers:
set(HEADERS_INTERNAL_X509
${PROJECT_SOURCE_DIR}/../include/c-spiffe/internal/x509util/certpool.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/internal/x509util/util.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_INTERNAL_X509}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/${TARGET_NAME}/x509util"
)

# Install Headers:
set(HEADERS_UTIL
${PROJECT_SOURCE_DIR}/../include/c-spiffe/utils/util.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/utils/stb_ds.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/utils/error.h
)
#   - *.h -> <prefix>/include/c-spiffe/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_UTIL}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}/utils"
)

# Install higher level header:
set(HEADERS_MOD_INTERNAL
${PROJECT_SOURCE_DIR}/../include/c-spiffe/internal/cryptoutil.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/internal/jwtutil.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/internal/pemutil.h
${PROJECT_SOURCE_DIR}/../include/c-spiffe/internal/x509util.h
)
#   - *.h -> <prefix>/include/c-spiffe/*.h
install(
    FILES ${HEADERS_MOD_INTERNAL}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}"
)
