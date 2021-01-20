# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "libspiffeid")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)


set(LIB_SPIFFEID 
${PROJECT_SOURCE_DIR}/src/id.c
${PROJECT_SOURCE_DIR}/src/match.c
${PROJECT_SOURCE_DIR}/src/trustdomain.c
)

add_library(${TARGET_NAME} SHARED ${LIB_SPIFFEID})
