# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2023 NXP
#

cmake_minimum_required(VERSION 3.10)

# This one is important
set(CMAKE_SYSTEM_NAME Linux)

set(CMAKE_SYSTEM_PROCESSOR x86_64)
if (DEFINED SYSTEM_PROCESSOR)
  set(CMAKE_SYSTEM_PROCESSOR ${SYSTEM_PROCESSOR})
endif()

if (NOT DEFINED ELE_LIB_PATH)
  set(ELE_LIB_PATH ../secure_enclave)
endif()

if (NOT DEFINED OPENSSL_PATH)
  set(OPENSSL_PATH ../openssl)
endif()

if (NOT DEFINED LIB_PATH)
  set(LIB_PATH ${CMAKE_SOURCE_DIR}/lib/${CMAKE_SYSTEM_PROCESSOR})
endif()

if (DEFINED TOOLCHAIN_PATH)
  # Specify the cross compiler
  set(CMAKE_C_COMPILER   ${TOOLCHAIN_PATH}-gcc)
  set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PATH}-g++)
  if (DEFINED TOOLCHAIN_ROOT_PATH)
    set(ZLIB_INCLUDE_DIR ${TOOLCHAIN_ROOT_PATH}/lib64/libz.so)
    # Where is the target environment
    set(CMAKE_FIND_ROOT_PATH  ${TOOLCHAIN_ROOT_PATH})
  endif()
endif()

# Search for programs in the build host directories
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# For libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# set the project name and version
project(Itest VERSION 2.0)

# the commit's SHA1, and whether the building workspace was dirty or not
execute_process(COMMAND
  git describe --match=NeVeRmAtCh --always --abbrev=8 --dirty
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE GIT_SHA1
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process(COMMAND
  git describe --match=NeVeRmAtCh --always --abbrev=8 --dirty
  WORKING_DIRECTORY "${ELE_LIB_PATH}"
  OUTPUT_VARIABLE GIT_SHA1_ELE_LIB
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

# the date of the commit
execute_process(COMMAND
  git log -1 --format=%ad --date=local
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE GIT_DATE
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

# the date of the commit
execute_process(COMMAND
  git log -1 --format=%ad --date=local
  WORKING_DIRECTORY "${ELE_LIB_PATH}"
  OUTPUT_VARIABLE GIT_DATE_ELE_LIB
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

configure_file(${Itest_SOURCE_DIR}/inc/version.h.in ${Itest_SOURCE_DIR}/inc/version.h )

# Notice name prefix of this variable, set by CMake according
# to value given with "project()" in the root CMakeLists.txt.
include_directories(${Itest_SOURCE_DIR}/inc)
include_directories(${OPENSSL_PATH}/include)
include_directories(${ELE_LIB_PATH}/include)
include_directories(${ELE_LIB_PATH}/include/hsm)
include_directories(${ELE_LIB_PATH}/include/hsm/internal)

file(GLOB SOURCES src/*/*.c src/*.c)
add_compile_options(-Wall -Wextra -fopenmp)
add_definitions(-DPSA_COMPLIANT)

find_package(ZLIB)
find_package(OpenMP)

# add the executable
add_executable(itest ${SOURCES})

#  -static
target_link_libraries(
  itest
  ${LIB_PATH}/libcrypto.a
  ${LIB_PATH}/libssl.a
  ${LIB_PATH}/libele_hsm.so
  ${LIB_PATH}/libele_hsm.so.1
  ${LIB_PATH}/libele_hsm.so.1.0
  z
  gomp.a
  pthread
  dl
  ${CMAKE_DL_LIBS}
)

target_include_directories(itest PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )

install(TARGETS itest DESTINATION ${CMAKE_INSTALL_BINDIR})
