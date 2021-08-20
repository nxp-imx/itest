#!/bin/bash

HELP=0
HOST_BUILD=0
BOARD_BUILD=1
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

rm -f itest
rm -rf build
mkdir build
cd build

if [ $BOARD_BUILD -eq 1 ]; then
   cmake ../ -DSECO_LIB_PATH=$SECO_LIB_PATH -DSYSTEM_PROCESSOR=$ARCH -DTOOLCHAIN_PATH=$TOOLCHAIN -DTOOLCHAIN_ROOT_PATH=$TOOLCHAIN_ENV_PATH
   make clean
   make -j4
   cp Itest ../itest
elif [ $HOST_BUILD -eq 1 ]; then
   cmake ../ -DSECO_LIB_PATH=$SECO_LIB_PATH -DSYSTEM_PROCESSOR=$ARCH
   make clean
   make -j4
   cp Itest ../itest
fi