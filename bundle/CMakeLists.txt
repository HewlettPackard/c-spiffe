# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

project(BUNDLE VERSION 0.0.1 LANGUAGES C)


set(LIB_BUNDLE 
${PROJECT_ROOT_DIR}/bundle/jwtbundle/src/bundle.c
${PROJECT_ROOT_DIR}/bundle/jwtbundle/src/set.c
${PROJECT_ROOT_DIR}/bundle/spiffebundle/src/bundle.c
${PROJECT_ROOT_DIR}/bundle/spiffebundle/src/set.c
${PROJECT_ROOT_DIR}/bundle/x509bundle/src/bundle.c
${PROJECT_ROOT_DIR}/bundle/x509bundle/src/set.c
)

add_library(libbundle SHARED ${LIB_BUNDLE})