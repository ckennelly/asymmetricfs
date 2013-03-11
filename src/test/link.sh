#!/bin/bash
FILE=`mktemp --tmpdir=.`

ln -s "${FILE}" "${FILE}-2"
echo 'foo' > "${FILE}"

test -L "${FILE-2}" || exit 1
test -s "${FILE-2}" || exit 2

rm -f "${FILE}" "${FILE}-2"
exit 0
