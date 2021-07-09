# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

file(COPY ../tests/resources/ DESTINATION ${PROJECT_BINARY_DIR}/bundle/x509bundle/tests/resources/)

add_executable(check_x509bundle check_bundle.c)

target_link_libraries(check_x509bundle bundle ${CHECK_LIBRARIES}
  spiffeid
  internal
  uriparser
  cjose
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_x509bundle check_x509bundle)

add_executable(check_x509set check_set.c)

target_link_libraries(check_x509set bundle ${CHECK_LIBRARIES}
  spiffeid
  internal
  uriparser
  cjose
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_x509set check_x509set)
