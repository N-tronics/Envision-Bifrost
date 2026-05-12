cmake_minimum_required(VERSION 3.10)
project(Bifrost)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
find_package(OpenSSL REQUIRED)

file (GLOB SOURCES "src/*.cpp")

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    include
    ${OPENSSL_INLCUDE_DIR}
)
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto)

