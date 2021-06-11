# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "svid")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_SVID 
${PROJECT_SOURCE_DIR}/x509svid/svid.c
${PROJECT_SOURCE_DIR}/jwtsvid/svid.c
${PROJECT_SOURCE_DIR}/../utils/util.c)

add_library(${TARGET_NAME} SHARED ${LIB_SVID})

# Install lib:
install(
    TARGETS              "${TARGET_NAME}"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)
# Install Headers:
set(HEADERS_X509SVID 
${PROJECT_SOURCE_DIR}/x509svid/svid.h
${PROJECT_SOURCE_DIR}/x509svid/verify.h
${PROJECT_SOURCE_DIR}/x509svid/source.h
)
#   - *.h -> <prefix>/include/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_X509SVID}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}/x509svid"
)

# Install Headers:
set(HEADERS_JWTSVID
${PROJECT_SOURCE_DIR}/jwtsvid/svid.h
)
#   - *.h -> <prefix>/include/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_JWTSVID}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}/jwtsvid"
)
