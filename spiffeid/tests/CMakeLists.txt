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

add_executable(check_id check_id.c)

target_link_libraries(check_id spiffeid ${CHECK_LIBRARIES}
  uriparser
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_id check_id)

add_executable(check_match check_match.c)

target_link_libraries(check_match spiffeid ${CHECK_LIBRARIES}
  uriparser
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_match check_match)

add_executable(check_trustdomain check_trustdomain.c)

target_link_libraries(check_trustdomain spiffeid ${CHECK_LIBRARIES}
  uriparser
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_trustdomain check_trustdomain)
