#!/bin/sh
#
# format.sh
#
# run clang-format on each .c & .h file

if [ -z "${CLANG_FORMAT}" ]; then
    CLANG_FORMAT=clang-format
fi

a=`git ls-files | grep "\.h$\|\.c$"`
for x in $a; do
     if [ $x != "config_in.h" ]; then
         $CLANG_FORMAT -i -style=file $x
     fi
done
