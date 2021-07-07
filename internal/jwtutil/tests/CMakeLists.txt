# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

file(COPY ../tests/resources/ DESTINATION ${PROJECT_BINARY_DIR}/internal/jwtutil/tests/resources/)

set(SOURCES_CHECK
  check_util.c 
  ../../cryptoutil/keys.c
  ../util.c
  ../../../include/c-spiffe/utils/stb_ds.h
)

add_executable(check_jwtutil ${SOURCES_CHECK})

target_link_libraries(check_jwtutil internal ${CHECK_LIBRARIES}
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
