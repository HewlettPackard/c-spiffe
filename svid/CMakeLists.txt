# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

project(SVID VERSION 0.0.1 LANGUAGES C)


set(LIB_SVID 
${PROJECT_ROOT_DIR}/svid/x509svid/src/svid.c
${PROJECT_ROOT_DIR}/svid/x509svid/src/verify.c
${PROJECT_ROOT_DIR}/utils/src/util.c)

add_library(libsvid SHARED ${LIB_SVID})
