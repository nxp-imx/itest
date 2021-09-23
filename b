#!/bin/bash +x

HELP=0
HOST_BUILD=0
BOARD_BUILD=1
FORCE_BUILD_JSON=0
SETUP_ENV=0
SECO_LIB_PATH=../seco_libs
ARCH=arm64
TOOLCHAIN=/opt/toolchains/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu
TOOLCHAIN_ENV_PATH=/opt/toolchains/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/aarch64-linux-gnu

while [[ $# -gt 0 ]]
do
    key="$1"

    case $key in
	-h)
	    HELP=1
	    shift
	    ;;
	-H)
	    HOST_BUILD=1
	    BOARD_BUILD=0
	    ARCH=x86_64
	    shift
	    ;;
	-S)
	    SECO_LIB_PATH=$2
	    shift
	    shift
	    ;;
	-f)
	    FORCE_BUILD_JSON=1
	    shift
	    ;;
	-s)
	    SETUP_ENV=1
	    shift
	    ;;
	-T)
	    TOOLCHAIN=$2
	    shift
	    shift
	    ;;
	-E)
	    TOOLCHAIN_ENV_PATH=$2
	    shift
	    shift
	    ;;
    esac
done

if [ $HELP -eq 1 ]; then
   echo "
build script:
-h: print this help
-H: build itest for host
-S <path>: path to seco_libs
-T <path>: path to the toolchain cc  (ex:/opt/toolchains/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu)
-E <path>: path to the toolchain env (ex:/opt/toolchains/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/aarch64-linux-gnu)
-f: force rebuild static lib json-c
-s: init git submodule (lib json-c)
   "
   exit 0
fi

if [ $SETUP_ENV -eq 1 ]; then
   git submodule update --init --recursive
   exit 0
fi

rm -f itest
rm -rf build
mkdir build
cd build

if [ $BOARD_BUILD -eq 1 ]; then

   if [ $FORCE_BUILD_JSON -eq 1 ]; then
       cd ../lib/json-c
       rm ../../$ARCH/libjson-c.a
       rm -rf build
       mkdir build
       cd build
       cmake ../ -DCMAKE_C_COMPILER=${TOOLCHAIN}-gcc
       make json-c-static
       cp libjson-c.a ../../$ARCH/libjson-c.a
       cd ../../../build
    fi

   cmake ../ -DSECO_LIB_PATH=$SECO_LIB_PATH -DSYSTEM_PROCESSOR=$ARCH -DTOOLCHAIN_PATH=$TOOLCHAIN -DTOOLCHAIN_ROOT_PATH=$TOOLCHAIN_ENV_PATH
   make clean
   make -j4
   cp Itest ../itest
elif [ $HOST_BUILD -eq 1 ]; then
   if [ $FORCE_BUILD_JSON -eq 1 ]; then
       cd ../lib/json-c
       rm ../../$ARCH/libjson-c.a
       rm -rf build
       mkdir build
       cd build
       cmake ../
       make json-c-static
       cp libjson-c.a ../../$ARCH/libjson-c.a
       cd ../../../build
    fi

   cmake ../ -DSECO_LIB_PATH=$SECO_LIB_PATH -DSYSTEM_PROCESSOR=$ARCH
   make clean
   make -j4
   cp Itest ../itest
fi