cmake_minimum_required(VERSION 3.10)

# This one is important
set(CMAKE_SYSTEM_NAME Linux)

set(CMAKE_SYSTEM_PROCESSOR x86_64)
if (DEFINED SYSTEM_PROCESSOR)
  set(CMAKE_SYSTEM_PROCESSOR ${SYSTEM_PROCESSOR})
endif()

if (NOT DEFINED SECO_LIB_PATH)
  set(SECO_LIB_PATH ../seco_libs)
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

configure_file(inc/ItestConfig.h.in inc/ItestConfig.h)

# Notice name prefix of this variable, set by CMake according
# to value given with "project()" in the root CMakeLists.txt.
include_directories(${Itest_SOURCE_DIR}/inc)
include_directories(${Itest_SOURCE_DIR}/lib/openssl-1.1.1h)
include_directories(${Itest_SOURCE_DIR}/${SECO_LIB_PATH}/include)
include_directories(${Itest_SOURCE_DIR}/${SECO_LIB_PATH}/include/hsm)
include_directories(${Itest_SOURCE_DIR}/lib/json-c)
include_directories(${Itest_SOURCE_DIR}/lib/json-c/build)

file(GLOB SOURCES src/*/*.c src/*.c)
add_compile_options(-Wall -Wextra -pedantic -Werror)

find_package(ZLIB)
find_package(OpenMP)
if (OPENMP_FOUND)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()

# add the executable
add_executable(Itest ${SOURCES})

target_link_libraries(
  Itest
  ${CMAKE_SOURCE_DIR}/${SECO_LIB_PATH}/she_lib.a
  ${CMAKE_SOURCE_DIR}/${SECO_LIB_PATH}/hsm_lib.a
  ${CMAKE_SOURCE_DIR}/${SECO_LIB_PATH}/seco_nvm_manager.a
  ${CMAKE_SOURCE_DIR}/lib/${CMAKE_SYSTEM_PROCESSOR}/libcrypto.a
  ${CMAKE_SOURCE_DIR}/lib/${CMAKE_SYSTEM_PROCESSOR}/libgomp.a
  ${CMAKE_SOURCE_DIR}/lib/${CMAKE_SYSTEM_PROCESSOR}/libssl.a
  ${CMAKE_SOURCE_DIR}/lib/${CMAKE_SYSTEM_PROCESSOR}/libjson-c.a
  z
  pthread
  dl
  ${CMAKE_DL_LIBS}
)

target_include_directories(Itest PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )
