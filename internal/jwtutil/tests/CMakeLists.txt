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

file(COPY ../tests/resources/ DESTINATION ${PROJECT_BINARY_DIR}/internal/jwtutil/tests/resources/)

set(SOURCES_CHECK
  check_util.c 
  ../../cryptoutil/keys.c
  ../util.c
  ../../../include/c-spiffe/utils/stb_ds.h
)

add_executable(check_jwtutil ${SOURCES_CHECK})

target_link_libraries(check_jwtutil internal ${CHECK_LIBRARIES}
  jansson
  cjose
  subunit
  check_pic
  check
  rt
  m
  crypto
  pthread)

add_test(check_jwtutil check_jwtutil)
