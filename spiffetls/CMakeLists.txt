# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "spiffetls")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_SPIFFETLS
${PROJECT_SOURCE_DIR}/tlsconfig/src/authorizer.c)

add_library(${TARGET_NAME} SHARED ${LIB_SPIFFETLS})
