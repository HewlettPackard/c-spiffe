# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

add_executable(check_endpoint check_endpoint.c)

target_link_libraries(check_endpoint spiffeid ${CHECK_LIBRARIES}
  uriparser
  jansson
  cjose
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_endpoint check_endpoint)
