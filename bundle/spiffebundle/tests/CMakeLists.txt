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

# add_executable(check_x509set check_set.c)

# target_link_libraries(check_x509set bundle ${CHECK_LIBRARIES}
#   spiffeid
#   internal
#   uriparser
#   jansson
#   cjose
#   subunit
#   check_pic
#   check
#   rt
#   m
#   crypto
#   pthread)

# add_test(check_x509set check_x509set)
