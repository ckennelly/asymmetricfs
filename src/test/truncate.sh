#!/bin/bash
FILE=`mktemp --tmpdir=.`

truncate --size=0 "${FILE}" || exit 1
truncate --size=5 "${FILE}" || exit 1
truncate --size=0 "${FILE}" || exit 1

if [ "${MODE}" = "rw" ]; then
    truncate --size=3 "${FILE}" || exit 1
    # There's a bit of a race condition in flushing the buffer and unmounting
    # the file system.
    truncate --size=5 "${FILE}" &
    wait || exit 1
fi
