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

file(COPY ../tests/resources/ DESTINATION ${PROJECT_BINARY_DIR}/spiffetls/tests/resources/)

add_executable(check_mode check_mode.c)

target_link_libraries(check_mode spiffetls ${CHECK_LIBRARIES}
  ssl
  spiffeid
  internal
  svid
  client
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

add_test(check_mode check_mode)

add_executable(check_dial check_dial.c)

target_link_libraries(check_dial spiffetls ${CHECK_LIBRARIES}
  ssl
  spiffeid
  internal
  svid
  client
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

add_test(check_dial check_dial)

add_executable(check_listen check_listen.c)

target_link_libraries(check_listen spiffetls ${CHECK_LIBRARIES}
  ssl
  spiffeid
  internal
  svid
  client
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

add_test(check_listen check_listen)

add_executable(check_peerid check_peerid.c)

target_link_libraries(check_peerid spiffetls ${CHECK_LIBRARIES}
  ssl
  spiffeid
  internal
  svid
  client
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

add_test(check_peerid check_peerid)

add_executable(tls_server resources/tls_server.c)

target_link_libraries(tls_server
  ssl
  crypto)

add_executable(tls_client resources/tls_client.c)

target_link_libraries(tls_client
  ssl
  crypto)
