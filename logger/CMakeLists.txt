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

set(TARGET_NAME "logger")

project(${TARGET_NAME} VERSION 0.0.1 LANGUAGES C)

set(LIB_LOGGER
${PROJECT_SOURCE_DIR}/logger.c
${PROJECT_SOURCE_DIR}/../utils/util.c
)

add_library(${TARGET_NAME} SHARED ${LIB_LOGGER})

# Install lib:
install(
    TARGETS              "${TARGET_NAME}"
    LIBRARY DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)

# Install higher level header:
set(HEADERS_MOD_LOGGER
${PROJECT_SOURCE_DIR}/../include/c-spiffe/logger/logger.h
)
#   - *.h -> <prefix>/include/c-spiffe/*.h
install(
    FILES ${HEADERS_MOD_LOGGER}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${C_SPIFFE_NAME}"
)
