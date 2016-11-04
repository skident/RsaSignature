cmake_minimum_required(VERSION 3.0)
project(RsaSignature)

# define the project
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

# which directories will be include to project. Used for includes in code
include_directories(${CMAKE_SOURCE_DIR})

# Find source files
file(GLOB INCLUDES *.hpp)
file(GLOB SOURCES *.cpp)

# Create exe
add_executable(${PROJECT_NAME} ${INCLUDES} ${SOURCES})

include(CMake/FindPoco.cmake)
set(ENV{POCO})
FIND_PACKAGE(Poco REQUIRED Crypto) 


if( Poco_FOUND )
    include_directories(${Poco_INCLUDE_DIRS})
    target_link_libraries(${PROJECT_NAME} ${Poco_LIBRARIES})
    message(STATUS "Using Poco ${Poco_VERSION}")
else()
    message(STATUS "Please include Poco by yourself")
endif()

FIND_PACKAGE(openssl)
if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    message(STATUS "Please include OpenSSL by yourself")
endif()




