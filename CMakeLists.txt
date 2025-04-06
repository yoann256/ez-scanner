cmake_minimum_required(VERSION 3.10)
project(EZ_Scanner)

# Include the directory where parson.h is located
include_directories(${CMAKE_SOURCE_DIR}/libs)

# Add the executable and link parson.c
add_executable(EZ_Scanner scanner.cpp)

# Link with OpenSSL and libcurl
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

target_include_directories(EZ_Scanner PRIVATE ${CURL_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(EZ_Scanner PRIVATE ${CURL_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)