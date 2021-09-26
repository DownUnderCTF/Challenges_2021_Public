#!/bin/bash

filename=$1

# for loop 
for i in {1..1000}; do
    # array of archives
    archives=('xz' 'bzip2' 'gzip' 'zip')
    # echo a random archive
    arch=${archives[RANDOM%4]}
    echo $arch
    if [ "$arch" = "zip" ]
    then
        # do format for zip
        cd challenge/
        zip ${filename}.zip $filename
        # remove the old file 
        rm $filename
        # echo archived file in challenge folder
        name=`ls`
        # rename archived file to original filename
        mv $name $filename
        cd ..
    else
        # archive with chosen archive
        $arch challenge/$filename
        # echo archived file in challenge folder
        name=`ls challenge/`
        # rename archived file to original filename
        mv challenge/$name challenge/$filename
    fi
done