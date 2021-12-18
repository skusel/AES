cmake_minimum_required(VERSION 3.21)

###############################################################################
# project description
###############################################################################
project(AES VERSION 1.0)

###############################################################################
# project dev tools info
###############################################################################
message(STATUS "CMake Version: ${CMAKE_VERSION}, System: ${CMAKE_SYSTEM}")
message(STATUS "CC - Compiler: ${CMAKE_C_COMPILER_ID}, Version: ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "CXX - Compiler: ${CMAKE_CXX_COMPILER_ID}, Version: ${CMAKE_CXX_COMPILER_VERSION}")
if(${CMAKE_BUILD_TYPE})
  message(STATUS "Using ${CMAKE_BUILD_TYPE} build type")
endif()

###############################################################################
# use C++17 standard
###############################################################################
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

###############################################################################
# add a couple of compiler flags to debug builds
###############################################################################
string(APPEND CMAKE_CXX_FLAGS_DEBUG " -Wall -Wextra -Werror")

###############################################################################
# options
###############################################################################
option(AES_ASAN "Turn on address sanitizer" OFF)
option(AES_USAN "Turn on undefined behavior sanitizer" OFF)
option(AES_BUILD_TESTING "Build AES tests when BUILD_TESTING is enabled" ${PROJECT_IS_TOP_LEVEL})

###############################################################################
# disable/enable sanitizers
###############################################################################
if(AES_ASAN)
  string(APPEND CMAKE_CXX_FLAGS " -fsanitize=address")
endif()
if(AES_USAN)
  string(APPEND CMAKE_CXX_FLAGS " -fsanitize=undefined")
endif()

###############################################################################
# generate compile_commands.json for vim and vscode
###############################################################################
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

###############################################################################
# set vars
###############################################################################
include(GNUInstallDirs)
set(AES_TARGET_NAME ${PROJECT_NAME})
set(AES_EXPORT_NAME ${AES_TARGET_NAME}Targets)
set(AES_BIN_INSTALL_DIR ${CMAKE_INSTALL_BINDIR})
set(AES_LIB_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR})
set(AES_INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR})

###############################################################################
# fetch thirdparty dependencies
###############################################################################
include(FetchContent)
#set(FETCHCONTENT_QUIET ON)
if(AES_BUILD_TESTING)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG e2239ee6043f73722e7aa812a459f54a28552929 # version 1.11.0
  )
  FetchContent_MakeAvailable(googletest)
endif()

###############################################################################
# add library
###############################################################################
set(AES_SRC
  src/aes.cpp
  src/aesblock.cpp
  src/aeskeysched.cpp
)
set(AES_HEADERS
  include/lskuse/aes.h
)
add_library(AES src/aes.cpp)
target_include_directories(AES PUBLIC include)

###############################################################################
# add library tests
###############################################################################
#if(AES_BUILD_TESTING)
#  # add google test
#  add_executable(AESTest tests/aes.cpp)
#  target_include_directories(AESTest PRIVATE src)
#  target_link_libraries(AESTest PUBLIC gtest_main AES)
#  include(GoogleTest)
#  gtest_discover_tests(AESTest XML_OUTPUT_DIR "${PROJECT_BINARY_DIR}/TestResults")
#endif()

###############################################################################
# make project installable
###############################################################################
install(TARGETS ${AES_TARGET_NAME}
  EXPORT ${AES_EXPORT_NAME}
  RUNTIME DESTINATION ${AES_BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${AES_LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${AES_LIB_INSTALL_DIR}
  INCLUDES DESTINATION ${AES_INCLUDE_INSTALL_DIR}
)
foreach(header ${AES_HEADERS})
  install(FILES ${header}
    DESTINATION ${AES_INCLUDE_INSTALL_DIR}/lskuse
  )
endforeach()

