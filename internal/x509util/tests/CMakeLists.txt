# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

file(COPY ../tests/resources/ DESTINATION ${PROJECT_BINARY_DIR}/internal/x509util/tests/resources/)

set(SOURCES_CHECK
  check_util.c
  ../src/util.c
  ../src/certpool.c
  ../../../utils/src/util.c
)

add_executable(check_x509util ${SOURCES_CHECK})

target_link_libraries(check_x509util libinternal ${CHECK_LIBRARIES}
  OpenSSL::SSL
  libspiffeid
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

add_test(check_x509util check_x509util)

set(SOURCES_CHECK
  check_certpool.c
  ../src/util.c
  ../src/certpool.c
  ../../../utils/src/util.c
)

add_executable(check_certpool ${SOURCES_CHECK})

target_link_libraries(check_certpool libsvid ${CHECK_LIBRARIES}
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

add_test(check_certpool check_certpool)
