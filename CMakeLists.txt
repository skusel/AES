cmake_minimum_required(VERSION 3.21)

###############################################################################
# project description
###############################################################################
project(skusel_aes VERSION 0.1.0)

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
option(SKUSEL_AES_ASAN "Turn on address sanitizer" OFF)
option(SKUSEL_AES_USAN "Turn on undefined behavior sanitizer" OFF)
option(SKUSEL_AES_BUILD_TESTING "Build SKUSEL_AES tests when BUILD_TESTING is enabled" PROJECT_IS_TOP_LEVEL)

###############################################################################
# disable/enable sanitizers
###############################################################################
if(SKUSEL_AES_ASAN)
  string(APPEND CMAKE_CXX_FLAGS " -fsanitize=address")
endif()
if(SKUSEL_AES_USAN)
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
set(SKUSEL_AES_TARGET_NAME ${PROJECT_NAME})
set(SKUSEL_AES_EXPORT_NAME ${SKUSEL_AES_TARGET_NAME}Targets)
set(SKUSEL_AES_BIN_INSTALL_DIR ${CMAKE_INSTALL_BINDIR})
set(SKUSEL_AES_LIB_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR})
set(SKUSEL_AES_INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR})

###############################################################################
# fetch thirdparty dependencies
###############################################################################
if(SKUSEL_AES_BUILD_TESTING)
  include(FetchContent)
  #set(FETCHCONTENT_QUIET ON)
  # Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP
  if(${CMAKE_VERSION} VERSION_EQUAL "3.24.0" OR ${CMAKE_VERSION} VERSION_GREATER "3.24.0")
    cmake_policy(SET CMP0135 NEW)
  endif()
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/f8d7d77c06936315286eb55f8de22cd23c188571.zip #v1.14.0
  )
  FetchContent_MakeAvailable(googletest)
endif()

###############################################################################
# create version header file
###############################################################################
configure_file(cmake/aesversion.h.in ${PROJECT_SOURCE_DIR}/include/skusel/aesversion.h)

###############################################################################
# add library
###############################################################################
set(SKUSEL_AES_SRC
  src/aes.cpp
  src/aesblock.cpp
  src/aeskeysched.cpp
)
set(SKUSEL_AES_HEADERS
  include/skusel/aes.h
  include/skusel/aesversion.h
)
add_library(${SKUSEL_AES_TARGET_NAME} ${SKUSEL_AES_SRC})
add_library(${PROJECT_NAME}::${SKUSEL_AES_TARGET_NAME} ALIAS ${SKUSEL_AES_TARGET_NAME})
target_include_directories(${SKUSEL_AES_TARGET_NAME} PUBLIC include)

###############################################################################
# add library tests
###############################################################################
if(SKUSEL_AES_BUILD_TESTING)
  message(STATUS "Adding ${SKUSEL_AES_TARGET_NAME} tests")
  include(CTest)
  # add google test
  add_executable(AESTests 
    tests/test_aeskeysched.cpp
    tests/test_aesblock.cpp
  )
  target_include_directories(AESTests PRIVATE src)
  target_link_libraries(AESTests PUBLIC gtest_main ${SKUSEL_AES_TARGET_NAME})
  include(GoogleTest)
  gtest_discover_tests(AESTests XML_OUTPUT_DIR "${PROJECT_BINARY_DIR}/TestResults")
endif()

###############################################################################
# make project installable
###############################################################################
install(TARGETS ${SKUSEL_AES_TARGET_NAME}
  EXPORT ${SKUSEL_AES_EXPORT_NAME}
  RUNTIME DESTINATION ${SKUSEL_AES_BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${SKUSEL_AES_LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${SKUSEL_AES_LIB_INSTALL_DIR}
  INCLUDES DESTINATION ${SKUSEL_AES_INCLUDE_INSTALL_DIR}
)
foreach(header ${SKUSEL_AES_HEADERS})
  install(FILES ${header}
    DESTINATION ${SKUSEL_AES_INCLUDE_INSTALL_DIR}/skusel
  )
endforeach()

