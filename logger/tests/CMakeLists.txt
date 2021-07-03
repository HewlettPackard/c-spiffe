# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

add_executable(check_logger check_logger.c)

target_link_libraries(check_logger logger ${CHECK_LIBRARIES}
  check
  subunit
  rt
  m
  pthread)

add_test(check_logger check_logger)
