#!/usr/bin/env bash

NTRU_HOME=$(dirname $0)/..

java \
    -jar "${NTRU_HOME}"/dist/ntru.jar \
    $@

exit $?
