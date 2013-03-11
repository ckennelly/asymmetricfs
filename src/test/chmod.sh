#!/bin/bash
FILE=`mktemp --tmpdir=.`

FAILED=0
for u in `seq 0 7`; do
    for g in `seq 0 7`; do
        for w in `seq 0 7`; do
            chmod "${u}${g}${w}" "${FILE}"
            ACTUAL=`stat -c "%a" "${FILE}"`

            if [ "${MODE}" = "wo" ]; then
                EXPECTED=$((${u}${g}${w} & 555))
            else
                EXPECTED="${u}${g}${w}"
            fi

            if [ "${ACTUAL}" -ne "${EXPECTED}" ]; then
                FAILED=1
            fi
        done
    done
done
rm -f "${FILE}"

# File does not exist.
(chmod 000 "${FILE}" 2> /dev/null) && (echo "Did not fail"; exit 2)

exit "${FAILED}"
