# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "c-spiffe")
project(${TARGET_NAME} VERSION 0.0.1)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE RelWithDebInfo)
set(protobuf_MODULE_COMPATIBLE TRUE)

# Enable debugging
set(CMAKE_BUILD_TYPE Debug)

# Show all warning messages
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

find_package(Protobuf CONFIG REQUIRED)
message(STATUS "Using protobuf ${Protobuf_VERSION}")

set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)
set(_REFLECTION gRPC::grpc++_reflection)

if(CMAKE_CROSSCOMPILING)
  find_program(_PROTOBUF_PROTOC protoc)
else()
  set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)
endif()

# Find gRPC installation
# Looks for gRPCConfig.cmake file installed by gRPC's cmake installation.
find_package(gRPC CONFIG REQUIRED)
message(STATUS "Using gRPC ${gRPC_VERSION}")

set(_GRPC_GRPCPP gRPC::grpc++)
if(CMAKE_CROSSCOMPILING)
  find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
else()
  set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)
endif()

find_package(OpenSSL REQUIRED)

# Set modules list
set(modules bundle internal spiffeid svid workload)

# Add projects
foreach(module ${modules})
  add_subdirectory(${module})
endforeach()

# Enable tests
option(ENABLE_TESTS "Enable unit testing" ON)

if (ENABLE_TESTS)

    # Enable Coverage Tests
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage -O0")

    find_package(Check REQUIRED)

    include(CheckCSourceCompiles)
    include(CheckCSourceRuns)
    include(CheckFunctionExists)
    include(CheckIncludeFile)
    include(CheckIncludeFiles)
    include(CheckLibraryExists)
    include(CheckSymbolExists)
    include(CheckTypeSize)

    enable_testing()
    add_subdirectory(${PROJECT_SOURCE_DIR}/svid/x509svid/tests)

    # Add build target to generate Coverage Test Report to all compiled object files
    find_program(GCOV gcov)
    find_program(LCOV lcov)
    find_program(GENHTML genhtml)
    if(NOT GCOV)
      message(FATAL_ERROR "gcov not found!")
    endif()
    if(NOT LCOV)
      message(FATAL_ERROR "lcov not found!")
    endif()
    if(NOT GENHTML)
      message(FATAL_ERROR "genhtml not found!")
    endif()

    add_custom_target(gcov
      COMMAND mkdir -p Coverage
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Testing
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )

    add_custom_command(TARGET gcov POST_BUILD
      COMMAND find ${CMAKE_BINARY_DIR} -type f -name *.c.o -exec ${GCOV} {} "\;"
      COMMAND echo "Coverage reports generated."
      COMMAND echo "You can find them on ${CMAKE_BINARY_DIR}/Coverage"
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/Coverage
      COMMENT "Coverage Reports Generated"
    )

    add_custom_target(lcov
      COMMAND mkdir -p Coverage
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Testing
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )

    add_custom_command(TARGET lcov POST_BUILD
      COMMAND ${LCOV} --directory .. --capture --output-file lcov.info
      COMMAND ${GENHTML} -o . lcov.info
      COMMAND echo "Coverage reports generated."
      COMMAND echo "You can find them on ${CMAKE_BINARY_DIR}/Coverage"
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/Coverage
      COMMENT "Coverage Reports Generated"
    )

    # Add 'Coverage' folder into clean target
    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES Coverage)
endif(ENABLE_TESTS)
