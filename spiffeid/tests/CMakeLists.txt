# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

add_executable(check_id check_id.c)

target_link_libraries(check_id libsvid ${CHECK_LIBRARIES}
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

add_test(check_id check_id)

add_executable(check_match check_match.c)

target_link_libraries(check_match libsvid ${CHECK_LIBRARIES}
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

add_test(check_match check_match)

add_executable(check_trustdomain check_trustdomain.c)

target_link_libraries(check_trustdomain libsvid ${CHECK_LIBRARIES}
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

add_test(check_trustdomain check_trustdomain)
