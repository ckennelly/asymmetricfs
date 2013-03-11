#!/bin/bash
FILE=`mktemp --tmpdir=.`
FILE2=`mktemp --tmpdir=.`

exec touch -r "${FILE}" "${FILE2}"
