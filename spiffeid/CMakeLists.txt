# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "spiffeid")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)


set(LIB_SPIFFEID 
${PROJECT_SOURCE_DIR}/src/id.c
${PROJECT_SOURCE_DIR}/src/match.c
${PROJECT_SOURCE_DIR}/src/trustdomain.c
${PROJECT_SOURCE_DIR}/../utils/src/util.c
)

add_library(${TARGET_NAME} SHARED ${LIB_SPIFFEID})

install(
    TARGETS              "${TARGET_NAME}"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)

# Headers:
set(HEADERS_SPIFFEID
${PROJECT_SOURCE_DIR}/src/id.h
${PROJECT_SOURCE_DIR}/src/match.h
${PROJECT_SOURCE_DIR}/src/trustdomain.h
)
#   - *.h -> <prefix>/include/${TARGET_NAME}/*.h
install(
    FILES ${HEADERS_SPIFFEID}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${TARGET_NAME}/src"
)
