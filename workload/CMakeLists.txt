# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

project(gRPC_CPP_Examples VERSION 0.0.1 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE RelWithDebInfo)

# Set sub_modules list
#set(sub_modules src)

#foreach(sub_module ${sub_modules})
add_subdirectory(src)
#endforeach()
