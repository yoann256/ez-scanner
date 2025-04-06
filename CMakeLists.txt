cmake_minimum_required(VERSION 3.10)
project(EZ_Scanner)

# Include the directory where parson.h is located
include_directories(${CMAKE_SOURCE_DIR}/libs)

# Add the executable and link parson.c
add_executable(EZ_Scanner scanner.cpp)

# If you're using Parson as a static library, you can add this instead:
add_library(parson STATIC libraries/parson/parson.c)
target_link_libraries(EZ_Scanner parson)
