# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

project(SPIFFEID VERSION 0.0.1 LANGUAGES C)


set(LIB_SPIFFEID 
${PROJECT_SOURCE_DIR}/src/id.c
${PROJECT_SOURCE_DIR}/src/match.c
${PROJECT_SOURCE_DIR}/src/trustdomain.c
)

add_library(libspiffeid SHARED ${LIB_SPIFFEID})
