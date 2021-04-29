# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

file(COPY ../tests/resources/ DESTINATION ${PROJECT_BINARY_DIR}/spiffetls/tlsconfig/tests/resources/)

add_executable(check_authorizer check_authorizer.c)

target_link_libraries(check_authorizer spiffetls ${CHECK_LIBRARIES}
  ssl
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

add_executable(check_config check_config.c)

target_link_libraries(check_config spiffetls ${CHECK_LIBRARIES}
  ssl
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

add_test(check_config check_config)