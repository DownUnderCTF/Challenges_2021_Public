#!/bin/sh

sage --pip install pycrypto tqdm

TMPDIR=`mktemp -d`
cp -r /work/challenge /work/solve "$TMPDIR"
cd "$TMPDIR/solve"
sage solve.sage
