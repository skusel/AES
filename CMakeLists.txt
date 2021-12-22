cmake_minimum_required(VERSION 3.21)

###############################################################################
# project description
###############################################################################
project(lskuse_aes VERSION 1.0)

###############################################################################
# project dev tools info
###############################################################################
if(PROJECT_IS_TOP_LEVEL)
  message(STATUS "CMake Version: ${CMAKE_VERSION}, System: ${CMAKE_SYSTEM}")
  message(STATUS "CC - Compiler: ${CMAKE_C_COMPILER_ID}, Version: ${CMAKE_C_COMPILER_VERSION}")
  message(STATUS "CXX - Compiler: ${CMAKE_CXX_COMPILER_ID}, Version: ${CMAKE_CXX_COMPILER_VERSION}")
  if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "")
    message(STATUS "Using ${CMAKE_BUILD_TYPE} build type")
  endif()
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
option(LSKUSE_AES_ASAN "Turn on address sanitizer" OFF)
option(LSKUSE_AES_USAN "Turn on undefined behavior sanitizer" OFF)
option(LSKUSE_AES_BUILD_TESTING "Build LSKUSE_AES tests when BUILD_TESTING is enabled" PROJECT_IS_TOP_LEVEL)

###############################################################################
# disable/enable sanitizers
###############################################################################
if(LSKUSE_AES_ASAN)
  string(APPEND CMAKE_CXX_FLAGS " -fsanitize=address")
endif()
if(LSKUSE_AES_USAN)
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
set(LSKUSE_AES_TARGET_NAME ${PROJECT_NAME})
set(LSKUSE_AES_EXPORT_NAME ${LSKUSE_AES_TARGET_NAME}Targets)
set(LSKUSE_AES_BIN_INSTALL_DIR ${CMAKE_INSTALL_BINDIR})
set(LSKUSE_AES_LIB_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR})
set(LSKUSE_AES_INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR})

###############################################################################
# fetch thirdparty dependencies
###############################################################################
include(FetchContent)
#set(FETCHCONTENT_QUIET ON)
if(LSKUSE_AES_BUILD_TESTING)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG e2239ee6043f73722e7aa812a459f54a28552929 # version 1.11.0
  )
  FetchContent_MakeAvailable(googletest)
endif()

###############################################################################
# create version header file
###############################################################################
configure_file(cmake/aesversion.h.in ${PROJECT_SOURCE_DIR}/include/lskuse/aesversion.h)

###############################################################################
# add library
###############################################################################
set(LSKUSE_AES_SRC
  src/aes.cpp
  src/aesblock.cpp
  src/aeskeysched.cpp
)
set(LSKUSE_AES_HEADERS
  include/lskuse/aes.h
  include/lskuse/aesversion.h
)
add_library(${LSKUSE_AES_TARGET_NAME} ${LSKUSE_AES_SRC})
add_library(${PROJECT_NAME}::${LSKUSE_AES_TARGET_NAME} ALIAS ${LSKUSE_AES_TARGET_NAME})
target_include_directories(${LSKUSE_AES_TARGET_NAME} PUBLIC include)

###############################################################################
# add library tests
###############################################################################
if(LSKUSE_AES_BUILD_TESTING)
  message(STATUS "Adding ${LSKUSE_AES_TARGET_NAME} tests")
  include(CTest)
  # add google test
  add_executable(AESTests 
    tests/test_aeskeysched.cpp
    tests/test_aesblock.cpp
  )
  target_include_directories(AESTests PRIVATE src)
  target_link_libraries(AESTests PUBLIC gtest_main ${LSKUSE_AES_TARGET_NAME})
  include(GoogleTest)
  gtest_discover_tests(AESTests XML_OUTPUT_DIR "${PROJECT_BINARY_DIR}/TestResults")
endif()

###############################################################################
# make project installable
###############################################################################
install(TARGETS ${LSKUSE_AES_TARGET_NAME}
  EXPORT ${LSKUSE_AES_EXPORT_NAME}
  RUNTIME DESTINATION ${LSKUSE_AES_BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LSKUSE_AES_LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LSKUSE_AES_LIB_INSTALL_DIR}
  INCLUDES DESTINATION ${LSKUSE_AES_INCLUDE_INSTALL_DIR}
)
foreach(header ${LSKUSE_AES_HEADERS})
  install(FILES ${header}
    DESTINATION ${LSKUSE_AES_INCLUDE_INSTALL_DIR}/lskuse
  )
endforeach()

