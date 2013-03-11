#!/bin/bash
#
# Verify that our choice of always attempting to open files for reading/writing
# is not harmful.
FILE=`mktemp --tmpdir=.`

echo 'foo' > "${FILE}"

# Alter underlying permissions.
chmod -r "${BASE}/${FILE}"

# Can't read.
test -r "${FILE}" || exit 1

# Can still write
(echo 'bar' >> "${FILE}") || exit 2

if [ "${MODE}" == "wo" ]; then
    # Early exit.
    exit 0
fi

# Restore read
chmod +r "${BASE}/${FILE}"

CONTENTS=`cat "${FILE}"`
if [ "${CONTENTS}" == "foo\nbar\n" ]; then
    exit 0
else
    exit 1
fi
