# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

file(COPY ../tests/resources/ DESTINATION ${PROJECT_BINARY_DIR}/svid/x509svid/tests/resources/)

add_executable(check_svid check_svid.c)

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

add_test(check_svid check_svid)

add_executable(check_verify check_verify.c)

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

add_test(check_verify check_verify)
