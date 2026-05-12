cmake_minimum_required(VERSION 3.10)
project(Bifrost)

set(CMAKE_CXX_STANDARD 17)
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
include_directories(include)
add_executable(Envision-Bifrost src/HMAC-SHA1.cpp src/utilities.cpp src/random.cpp src/Diffie-Hellman.cpp)
target_link_libraries(Envision-Bifrost OpenSSL::Crypto)

