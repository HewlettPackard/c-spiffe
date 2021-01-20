# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "libsvid-tests")

add_executable(${TARGET_NAME} ./check_svid.c)

target_link_libraries(${TARGET_NAME} libsvid ${CHECK_LIBRARIES}
  OpenSSL::SSL
  libsvid
  libspiffeid
  libinternal
  uriparser
  libbundle
  jansson
  cjose
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_svid ${TARGET_NAME})
