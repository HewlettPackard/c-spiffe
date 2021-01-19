# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

project(INTERNAL VERSION 0.0.1 LANGUAGES C)


set(LIB_INTERNAL 
${PROJECT_ROOT_DIR}/internal/cryptoutil/src/keys.c
${PROJECT_ROOT_DIR}/internal/jwtutil/src/util.c
${PROJECT_ROOT_DIR}/internal/pemutil/src/pem.c
${PROJECT_ROOT_DIR}/internal/x509util/src/certpool.c
${PROJECT_ROOT_DIR}/internal/x509util/src/util.c
)

add_library(libinternal SHARED ${LIB_INTERNAL})