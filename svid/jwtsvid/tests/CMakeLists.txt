# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

file(COPY ../tests/resources/ DESTINATION ${PROJECT_BINARY_DIR}/svid/jwtsvid/tests/resources/)

add_executable(check_jwtsvid check_svid.c)

target_link_libraries(check_jwtsvid svid ${CHECK_LIBRARIES}
  spiffeid
  internal
  client
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

add_test(check_jwtsvid check_jwtsvid)
