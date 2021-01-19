# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

project(SPIFFEID VERSION 0.0.1 LANGUAGES C)


set(LIB_SPIFFEID 
${PROJECT_ROOT_DIR}/spiffeid/src/id.c
${PROJECT_ROOT_DIR}/spiffeid/src/match.c
${PROJECT_ROOT_DIR}/spiffeid/src/trustdomain.c
)

add_library(libspiffeid SHARED ${LIB_SPIFFEID})
