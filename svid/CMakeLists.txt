# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "svid")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_SVID 
${PROJECT_SOURCE_DIR}/x509svid/src/svid.c
${PROJECT_SOURCE_DIR}/x509svid/src/verify.c
${PROJECT_SOURCE_DIR}/jwtsvid/src/svid.c
${PROJECT_SOURCE_DIR}/../utils/src/util.c)

add_library(${TARGET_NAME} SHARED ${LIB_SVID})
