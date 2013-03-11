#!/bin/bash
FILE=`mktemp --tmpdir=.`
echo 'foo' > "${FILE}"

if [ "${MODE}" = "wo" ]; then
    exit 0
fi

exec diff -au "${FILE}" - << 'EOF'
foo
EOF
