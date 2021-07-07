# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

add_executable(check_keys check_keys.c)

target_link_libraries(check_keys internal ${CHECK_LIBRARIES}
  cjose
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_keys check_keys)
