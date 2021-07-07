# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

file(COPY ../tests/resources/ DESTINATION ${PROJECT_BINARY_DIR}/svid/x509svid/tests/resources/)

add_executable(check_x509svid check_svid.c)

target_link_libraries(check_x509svid svid ${CHECK_LIBRARIES}
  spiffeid
  internal
  uriparser
  bundle
  cjose
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_x509svid check_x509svid)
