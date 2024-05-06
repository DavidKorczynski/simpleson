#!/bin/bash
mkdir fuzz-build
cd fuzz-build
cmake -DCMAKE_VERBOSE_MAKEFILE=ON ../
make V=1 || true

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $SRC/fuzzer.cpp -Wl,--whole-archive $SRC/simpleson/fuzz-build/libsimpleson.a -Wl,--allow-multiple-definition -I$SRC/simpleson/  -o $OUT/fuzzer
