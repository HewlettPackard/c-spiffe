
cmake_minimum_required(VERSION 3.13)
set(TARGET_NAME "workload_test")
project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C CXX)

file(COPY ./resources/ DESTINATION ${PROJECT_BINARY_DIR}/resources/)

# Include generated *.pb.h files
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../)

add_executable(check_client "./check_client.cc")

target_link_libraries(check_client ${CHECK_LIBRARIES} 
  client
  gtest
  gmock
  gmock_main)

add_test(check_client check_client)

add_executable(check_watcher "./check_watcher.c")

target_link_libraries(check_watcher ${CHECK_LIBRARIES} 
  client)

add_test(check_watcher check_watcher)

add_executable(check_jwtwatcher "./check_jwtwatcher.c")

target_link_libraries(check_jwtwatcher ${CHECK_LIBRARIES} 
  client)

add_test(check_jwtwatcher check_jwtwatcher)

add_executable(check_x509source "./check_x509source.c")

target_link_libraries(check_x509source ${CHECK_LIBRARIES} 
  source)

add_test(check_x509source check_x509source)

add_executable(check_jwtsource "./check_jwtsource.c")

target_link_libraries(check_jwtsource ${CHECK_LIBRARIES}
  source)

add_test(check_jwtsource check_jwtsource)
