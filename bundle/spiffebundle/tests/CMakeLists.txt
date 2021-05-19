# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

file(COPY ../tests/resources/ DESTINATION ${PROJECT_BINARY_DIR}/bundle/spiffebundle/tests/resources/)

add_executable(check_spiffebundle check_bundle.c)

target_link_libraries(check_spiffebundle bundle ${CHECK_LIBRARIES}
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

add_test(check_spiffebundle check_spiffebundle)

add_executable(check_spiffeset check_set.c)

target_link_libraries(check_spiffeset bundle ${CHECK_LIBRARIES}
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

add_test(check_spiffeset check_spiffeset)
