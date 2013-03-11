#!/bin/bash
FILE=`mktemp --tmpdir=.`

echo 'foo' > "${FILE}"
mv "${FILE}" "${FILE}-2"

if [ "${MODE}" == "rw" ]; then
    test -e "${FILE}-2" || exit 1
    CONTENTS=`cat "${FILE}-2"`
    if [ "${CONTENTS}" == "foo\n" ]; then
        exit 0
    else
        exit 1
    fi
fi

exit 0
