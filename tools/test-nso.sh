#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
classes=$(mktemp -d)
trap 'rm -rf "$classes"' EXIT
javac --release 17 -d "$classes" \
    "$root/app/src/main/java/org/sidikkkkk/switchport/NsoHeader.java" \
    "$root/tools/NsoHeaderTest.java"
java -cp "$classes" org.sidikkkkk.switchport.NsoHeaderTest "$@"
