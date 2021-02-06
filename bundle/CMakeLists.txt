# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "libbundle")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_BUNDLE 
${PROJECT_SOURCE_DIR}/jwtbundle/src/bundle.c
${PROJECT_SOURCE_DIR}/jwtbundle/src/set.c
${PROJECT_SOURCE_DIR}/jwtbundle/src/source.c
${PROJECT_SOURCE_DIR}/spiffebundle/src/bundle.c
${PROJECT_SOURCE_DIR}/spiffebundle/src/set.c
${PROJECT_SOURCE_DIR}/x509bundle/src/bundle.c
${PROJECT_SOURCE_DIR}/x509bundle/src/set.c
${PROJECT_SOURCE_DIR}/x509bundle/src/source.c
)

add_library(${TARGET_NAME} SHARED ${LIB_BUNDLE})
