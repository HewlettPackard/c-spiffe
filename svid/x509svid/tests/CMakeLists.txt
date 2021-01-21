# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

add_executable(check_svid check_svid.c)
add_executable(check_verify check_verify.c)

target_link_libraries(check_svid libsvid ${CHECK_LIBRARIES}
  OpenSSL::SSL
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

  target_link_libraries(check_verify libsvid ${CHECK_LIBRARIES}
  OpenSSL::SSL
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

add_test(NAME check_svid COMMAND ${CMAKE_COMMAND})
add_test(NAME check_verify COMMAND ${CMAKE_COMMAND})
set_tests_properties(check_svid PROPERTIES TIMEOUT 30)
