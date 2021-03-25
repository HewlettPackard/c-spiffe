# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

add_executable(check_authorizer check_authorizer.c)

target_link_libraries(check_authorizer spiffetls ${CHECK_LIBRARIES}
  OpenSSL::SSL
  spiffeid
  internal
  svid
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

add_test(check_authorizer check_authorizer)