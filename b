#!/bin/bash +x

NPROC=$(nproc)
WORKDIR=$PWD
HELP=0
ARCH_BUILD=0
FORCE_BUILD_JSON=0
SETUP_ENV=0
SETUP_OPTION="submodule"
RESET_ENV=0
SECO_LIB_PATH=$WORKDIR/lib/seco_lib
ARCH=arm64
PLATFORM=linux-aarch64

if [ -z "${CC}" ]; then
    export CC=gcc
fi
if [ -z "${AR}" ]; then
    export AR=ar
fi

while [[ $# -gt 0 ]]
do
    key="$1"

    case $key in
	-h)
	    HELP=1
	    shift
	    ;;
	-H)
	    ARCH_BUILD=1
	    ARCH=$2
	    shift
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
        SETUP_OPTION=$2
	    shift
        shift
	    ;;
	-r)
	    RESET_ENV=1
	    shift
	    ;;
    esac
done

if [ $HELP -eq 1 ]; then
   echo "
build script:
-h: print this help
-H <ARCH>: Set target Arch (default=arm64 or x86_64)
-S <path>: path to seco_libs
-f: force rebuild static lib seco_lib, json-c, openssl
-s <OPTION>: option(all/submodule) init git submodule (lib seco_lib, json-c, openssl)
-r: reset env (clean repo and submodule)
   "
   exit 0
fi

if [ $ARCH == arm64 ]; then
    PLATFORM=linux-aarch64
elif [ $ARCH == x86_64 ]; then
    PLATFORM=linux-x86_64
fi

if [ $SETUP_ENV -eq 1 ]; then
   if [ $SETUP_OPTION == "submodule" ]; then
      git submodule update --init --recursive
      exit 0
   elif [ $SETUP_OPTION == "toolchain" ]; then
      wget --no-check-certificate https://releases.linaro.org/components/toolchain/binaries/latest-7/aarch64-linux-gnu/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu.tar.xz
      echo "Extrating toolchain..."
      sudo tar -xf gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu.tar.xz -C /opt/
      echo "export PATH=/opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/bin/:$PATH
export CC=/opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-gcc
export AR=/opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-ar
export CROSS_COMPILE=aarch64-linux-gnu-
export ARCH=arm64
export SDKTARGETSYSROOT=/opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/aarch64-linux-gnu/
export INCLUDEDIR=/opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/include
" > setup_linaro_aarch64.sh
      sudo mv setup_linaro_aarch64.sh /opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/setup_linaro_aarch64.sh
      sudo chmod +x /opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/setup_linaro_aarch64.sh
      echo "Install zlib..."
      sudo cp lib/zlib1.2.11_aarch64/zlib.h /opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/aarch64-linux-gnu/libc/usr/include/zlib.h
      sudo cp lib/zlib1.2.11_aarch64/zconf.h /opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/aarch64-linux-gnu/libc/usr/include/zconf.h
      sudo cp lib/zlib1.2.11_aarch64/libz.so /opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/aarch64-linux-gnu/lib64/libz.so
      sudo cp lib/zlib1.2.11_aarch64/libz.so.1.2.11 /opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/aarch64-linux-gnu/lib64/libz.so.1.2.11
      echo "to use the toolchain: source /opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/setup_linaro_aarch64.sh"
      rm gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu.tar.xz
      exit 0
   fi
fi

if [ $RESET_ENV -eq 1 ]; then
   git clean -xfd
   git submodule foreach --recursive git clean -xfd
   git reset --hard
   git submodule foreach --recursive git reset --hard
   git submodule update --init --recursive
   exit 0
fi

rm -f itest
rm -rf build
mkdir build
cd build

if [ $ARCH_BUILD -eq 1 ]; then
   if [ $FORCE_BUILD_JSON -eq 1 ]; then
       rm -rf $WORKDIR/lib/$ARCH
       mkdir -p $WORKDIR/lib/$ARCH
       # build json-c
       cd $WORKDIR/lib/json-c
       rm ../../$ARCH/libjson-c.als
       rm -rf build
       mkdir build
       cd build
       cmake ../
       make -j$NPROC json-c-static
       cp libjson-c.a ../../$ARCH/libjson-c.a
       # build seco lib
       cd $WORKDIR
       cd $SECO_LIB_PATH
       make clean && make all -j$NPROC
       cp *.a $WORKDIR/lib/$ARCH
       # build openssl
       cd $WORKDIR/lib/openssl
       ./Configure $PLATFORM
       make clean && make -j$NPROC CC="$CC" AR="$AR"
       cp *.a $WORKDIR/lib/$ARCH
       cd $WORKDIR/build
    fi

   cmake ../ -DSECO_LIB_PATH=$SECO_LIB_PATH -DSYSTEM_PROCESSOR=$ARCH
   make clean
   make -j$NPROC
   cp Itest ../itest
fi