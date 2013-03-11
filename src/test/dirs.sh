#!/bin/bash
DIR=`mktemp -d --tmpdir=.`
ls "${DIR}"                 || exit 1
rmdir "${DIR}"              || exit 1

exit 0
