# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(SOURCES_CHECK
  check_util.c 
  ../../cryptoutil/src/keys.c
  ../src/util.c
  ../../../utils/src/stb_ds.h
)

add_executable(check_jwtutil ${SOURCES_CHECK})

target_link_libraries(check_jwtutil internal ${CHECK_LIBRARIES}
  spiffeid
  uriparser
  bundle
  jansson
  cjose
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_jwtutil check_jwtutil)
