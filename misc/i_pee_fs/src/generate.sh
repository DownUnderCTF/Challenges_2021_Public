#!/bin/sh

# allocate a 64MB file

dd if=/dev/urandom of=data bs=4M count=16
mkfs.fat -F 16 data
mkdir -p test
sudo mount data test
sudo dd if=/dev/urandom 'of=test/00 literal garbage ignore' bs=4M count=6
sudo cp -r dir/* test
sudo umount data
rmdir test
