#!/bin/sh

TMPDIR=`mktemp -d`

cp -r /work/challenge /work/solve "$TMPDIR"
cd "$TMPDIR/solve"
sage solve.sage
