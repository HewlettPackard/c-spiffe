# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

file(COPY ../tests/resources/ DESTINATION ${PROJECT_BINARY_DIR}/bundle/jwtbundle/tests/resources/)

add_executable(check_jwtbundle check_bundle.c)

target_link_libraries(check_jwtbundle bundle ${CHECK_LIBRARIES}
  spiffeid
  internal
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

add_test(check_jwtbundle check_jwtbundle)

add_executable(check_jwtset check_set.c)

target_link_libraries(check_jwtset bundle ${CHECK_LIBRARIES}
  spiffeid
  internal
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

add_test(check_jwtset check_jwtset)
