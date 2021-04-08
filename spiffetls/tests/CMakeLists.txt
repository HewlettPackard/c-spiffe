# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

add_executable(check_mode check_mode.c)

target_link_libraries(check_mode spiffetls ${CHECK_LIBRARIES}
  OpenSSL::SSL
  spiffeid
  internal
  svid
  source
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

add_test(check_mode check_mode)

add_executable(check_dial check_dial.c)

target_link_libraries(check_dial spiffetls ${CHECK_LIBRARIES}
  OpenSSL::SSL
  spiffeid
  internal
  svid
  source
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

add_test(check_dial check_dial)