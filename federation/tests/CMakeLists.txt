# (C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP
#
# 
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# 
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# 
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# Minimum CMake required
cmake_minimum_required(VERSION 3.13)
file(COPY ../tests/resources/ DESTINATION ${PROJECT_BINARY_DIR}/federation/tests/resources/)

add_executable(check_endpoint check_endpoint.c)

target_link_libraries(check_endpoint bundle federation ${CHECK_LIBRARIES}
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

add_test(check_endpoint check_endpoint)

add_executable(check_spiffebundle_source check_spiffebundle_source.c)

target_link_libraries(check_spiffebundle_source bundle federation ${CHECK_LIBRARIES}
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

add_test(check_spiffebundle_source check_spiffebundle_source)

add_executable(check_spiffebundle_watcher check_watcher.c)

target_link_libraries(check_spiffebundle_watcher bundle federation ${CHECK_LIBRARIES}
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

add_test(check_spiffebundle_watcher check_spiffebundle_watcher)

add_executable(check_spiffebundle_server check_server.c)

target_link_libraries(check_spiffebundle_server bundle federation ${CHECK_LIBRARIES}
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

add_test(check_spiffebundle_server check_spiffebundle_server)
