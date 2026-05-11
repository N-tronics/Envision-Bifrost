cmake_minimum_required(VERSION 3.10)
project(Bifrost)

set(CMAKE_CXX_STANDARD 17)
find_package(OpenSSL REQUIRED)
include_directories(include)
add_executable(Envision-Bifrost src/main.cpp src/HMAC-SHA1.cpp)
target_link_libraries(Envision-Bifrost OpenSSL::Crypto)

