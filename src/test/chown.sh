#!/bin/bash
FILE=`mktemp --tmpdir=.`
chown "${USER}" "${FILE}" || exit 1
rm -f "${FILE}"
