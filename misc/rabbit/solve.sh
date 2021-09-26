#!/bin/bash

echo "DUCTF - Rabbit Solve Script"
echo "Note: This script assumes you have the original 'flag.txt' file in a folder called 'challenge'!"
echo ""

echo -n "Go solve script! Solve!"
# Setting Variables for Stats
gzip_num=0
bzip2_num=0
xz_num=0
zip_num=0
num_loop=0

while true; do
    echo -e "\r\033[1A\033[0KLoop #: $num_loop"
    num_loop=$((num_loop+1))
    filename=`ls challenge/`
    checktype=`file challenge/$filename`
    num_files=`ls challenge/ | wc -l`
    # Must have only one file in the challenge folder
    if [ "$num_files" != "1" ]; then
        echo "No file in the 'challenge' folder or too many files in 'challenge' folder ! Aborting script!"
        break
    # If it is an ASCII text file, it is probably the flag and should print out the flag
    elif echo $checktype | grep -q "ASCII"; then 
        cat challenge/$filename
        echo "The flag is: `base64 -d challenge/$filename`"
        echo ""
        echo "Stat Breakdown"
        echo "-----------------"
        echo "# of gzips decompressed: $gzip_num"
        echo "# of bzip2s decompressed: $bzip2_num"
        echo "# of xzs decompressed: $xz_num"
        echo "# of zips decompressed: $zip_num"
        echo ""
        break
    # If bzip2, change extension to .bz2 and decompress
    elif echo $checktype | grep -q "bzip2"; then
        mv challenge/$filename challenge/${filename}.bz2
        bzip2 -d -q challenge/${filename}.bz2
        bzip2_num=$((bzip2_num+1))
    # If xz, change extension to .xz and decompress
    elif echo $checktype | grep -q "XZ"; then
        mv challenge/$filename challenge/${filename}.xz
        unxz -q challenge/${filename}.xz
        xz_num=$((xz_num+1))
    # If gzip, change extension to .gz and decompress
    elif echo $checktype | grep -q "gzip"; then
        mv challenge/$filename challenge/${filename}.gz
        gunzip -q challenge/${filename}.gz
        gzip_num=$((gzip_num+1))
    # Zip was a bit of a pain to work with honestly. 
    # If you didn't cd into the directory there would be an 
    # issue where it would always think it was a zip archive
    # Also when decompressing zip archives it usually keeps the old 
    # file so I just deleted the zip archive after decompressing it.
    elif echo $checktype | grep -q "Zip archive data"; then
        cd challenge/
        mv $filename ${filename}.zip
        unzip -q ${filename}.zip
        rm ${filename}.zip
        cd ..
        zip_num=$((zip_num+1))
    # Was used as a debugging statement if I need to add a new decompression method
    else
        echo "No filetype match! Edit script to accomdate for: ${checktype}"
    fi
done
