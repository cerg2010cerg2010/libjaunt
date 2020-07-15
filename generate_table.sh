#!/bin/sh
# This generates an instruction table from thumb-op-fuzzer output.
# See https://github.com/cerg2010cerg2010/thumb-op-fuzzer
# Note: uses espresso logic minimizer. Build & install it before
# running this script.
# You can get it here: https://github.com/classabbyamp/espresso-logic

TMP=/tmp
INPUT=

if [ $# -eq 1 ]; then
	INPUT=$1
elif [ $# -eq 2 ]; then
	INPUT=$1
	TMP=$2
else
	echo 'No input file specified'
	exit 1
fi

c++ -O2 converter.cpp -o "$TMP/converter"
./bitprint.awk "$INPUT" | espresso -Dd1merge | espresso -o kiss | "$TMP/converter" | sed 's/^\(0x[0-9a-zA-Z]\+\)\s\+\(0x[0-9a-zA-Z]\+\)$/{ \2, \1 },/'

