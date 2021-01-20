# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

project(INTERNAL VERSION 0.0.1 LANGUAGES C)


set(LIB_INTERNAL 
${PROJECT_SOURCE_DIR}/cryptoutil/src/keys.c
${PROJECT_SOURCE_DIR}/jwtutil/src/util.c
${PROJECT_SOURCE_DIR}/pemutil/src/pem.c
${PROJECT_SOURCE_DIR}/x509util/src/certpool.c
${PROJECT_SOURCE_DIR}/x509util/src/util.c
)

add_library(libinternal SHARED ${LIB_INTERNAL})
